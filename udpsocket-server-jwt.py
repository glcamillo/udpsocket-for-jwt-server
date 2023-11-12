#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Autor: G Camillo
# Last revision:20231111

"""
Program (Python Script) that creates a UDP socket server and implements a simple protocol for receiving
 simple information in the form of JWT.
Main goal: laboratory used by limited group of students (UFSC-DEC7557) to send information about their members.
Resources used: UDP sockets; JWT tokens (JWS); signing and checking JWS

Description found in Readme.md.
"""

# Set debugging messages - flag to printout log messages in screen
printout_in_screen: bool = True

import datetime
import hashlib  # For create ID with hash of request payload
import jwt
import os
import pathlib
import random
import secrets
import sys
import traceback


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from jwt import InvalidSignatureError, InvalidTokenError, InvalidAlgorithmError, InvalidKeyError, DecodeError
from socket import socket, AF_INET, SOCK_DGRAM

""" JWT definitions
    Algorithms accepted from users posting JWS:
    “alg":RS256     RSASSA-PKCS1-v1_5 using SHA-256
    "alg":ES256     ECDSA using P-256 and SHA-256
    Algorithm used for signature of responses:
    "alg":HS256     HMAC using SHA-256    
"""
jwt_algorithms = ("RS256", "ES256", "HS256")
jwt_validity = 30  # exp=iat+30s validity of token
jwt_audience = "udp.socket.server.for.jwt"  # this server

"""
    FSM (Finite State Machine) of the protocol
    Seven states and they are associated with colors (not needed)
"""
NUM_STATES = 7  # 0:start  6:end
STATE_MIN = 0
STATE_MAX = 6
PROTOCOL_STATES = ("RED", "ORANGE", "YELLOW", "GREEN", "BLUE", "INDIGO", "VIOLET",)

MAX_NUM_FAULTS = 1

# The group HEARTBEAT if for testing purposes
GROUP_NAMES = ('GUILHONGA', 'CHEDIMON', 'SEGSANH', 'THEOTHERS', 'HEARTBEAT')


class Groups(object):
    """ Class of groups: information ABOUT the group and ABOUT processing the
        messages received
        num_members: how many members in this group -> int
        members: list of members (number of registration) -> Tuple
        last_num_received: controls in which fase of protocol -> int
           FSM (finite state machine), because we use UDP
        num_faults: inserts some faults in the responses (to check
           the client processing)
        """

    def __init__(self, name, num_members, members, last_num_received, num_faults=2):
        # Info about group
        self.name = name
        self.num_members = num_members
        self.members = members

        # About processing
        self.last_num_received = last_num_received
        self.num_faults = MAX_NUM_FAULTS

        # What number of registration (member) the group already posted
        self.members_received = {}
        for member in members:
            self.members_received[member] = False

    def get_last_n_received(self):
        return self.last_num_received

    def get_n_faults(self):
        return self.num_faults

    def get_number_members(self):
        return self.num_members

    def set_last_n_received(self, n_state):
        """:param n_state what state in the FSM processing"""
        self.last_num_received = n_state

    def set_n_faults(self, n_fault):
        """:param n_fault sets the number of faults in FSM processing"""
        self.num_faults = n_fault

    def  add_member_registration(self, registration):
        if not self.members_received[registration]:
            self.members_received[registration] = True


#  This will contain the public keys loaded from files.
#  Each group will be associated with a public key.
#  Example: group HEARTBEAT -> heartbeat.pem|ssh   (formats: SSH or PEM)
public_keys = {}

# Directories that contains the keys
dir_of_priv_keys = "keys_priv"
file_secret_key = "keys_priv/key_secret_for_hmac.txt"
dir_of_pub_keys = "keys_pub"
# Logs contect: basic error handling
log_file = "log-for-udpserver-jwt.txt"
# Logs content: timestamp:ip:port:REQUEST_CONTENT_CODED
log_file_conn = 'dec7557-log-connection_and_request.txt'
# Logs content: timestamp:group_name:PAYLOADS:OK | NOTOK (signature verification)
log_file_content = 'dec7557-log-group_and_payload.txt'
# Logs content for responses: timestamp:group_name:PAYLOAD|JWS
log_file_responses = 'dec7557-log-group_and_responses.txt'
# Logs content: timestamp:grupo_name:SUCESS:all tokens sended (but without confirmation)
log_file_sucess = 'dec7557-log-sucess.txt'
log_file_registration_numbers = 'dec7557-log-group-registration-members.txt'
log_response_pay = "dec7557-response-payloads.txt"
log_response_jwt = "dec7557-response-JWT.txt"


#     Data initialization
guilhonga = Groups("GUILHONGA", 2, (23250033, 23150814), 0)
chedimon = Groups("CHEDIMON", 2, (21203167, 21203171), 0)
segsanh = Groups("SEGSANH", 2, (21204790, 21200606), 0)
theothers = Groups("THEOTHERS", 3, (20105143, 21203170, 21101364), 0)
heartbeat = Groups("HEARTBEAT", 1, (222222,), 0)  # insert a comma to python recognize as a tuple

groups = {'HEARTBEAT': heartbeat,
          'CHEDIMON': chedimon,
          'GUILHONGA': guilhonga,
          'SEGSANH': segsanh,
          'THEOTHERS': theothers}

secret_key = None


def print_log(message):
    if printout_in_screen:
        print(f"{message}")
    else:
        pass


def read_public_keys(base_dir):
    """ Read the public keys from directory specified by global variable: dir_of_pub_keys
         The key data is writen in the dic public_keys
         Two types of publics keys:
         - PEM format created by cyberchef.org or by OpenSSL
         - SSH format generated by ssh-keygen
    """
    print_log("\n -- Reading Public Keys --- \n")
    # We will use the base dir from parameter supplied in command line
    path = pathlib.Path(base_dir + "/" + dir_of_pub_keys)
    #  path = pathlib.Path(os.getcwd() + "/" + dir_of_pub_keys)

    # Read the public key in PEM format generated by cyberchef and openssl
    for f in path.rglob("*.pem"):
        with open(f, 'r') as file:
            file_content = file.read()
            print_log(f"-- Public Key: {path}\n")
            print_log(file_content)
            # filename_full = f.name -> filename = filename_full.strip('.')[0]
            # The final path component, without its suffix:
            filename = f.stem
            if filename.upper() in GROUP_NAMES:
                public_keys[filename.upper()] = file_content

    # Read the public key in SSH format
    for f in path.rglob("*.ssh"):
        with open(f, 'r') as file:
            file_content = file.read()
            print_log(f"-- Public Key: {path}\n")
            print_log(file_content)
            filename = f.stem
            if filename.upper() in GROUP_NAMES:
                key_pub = serialization.load_ssh_public_key(file_content.encode())
                if isinstance(key_pub, rsa.RSAPublicKey):
                    public_keys[filename.upper()] = key_pub


def read_secret_key(base_dir) -> str:
    """    Obs.: the secret_key is initialized with None
    :param base_dir: the base directory: /keys_priv/key_secret_for_hmac.txt The file contains de passphrase in
                    bytes without new line.
    :return: the secret key (passphrase) in BYTES (encoded) without new line.
    """
    print_log("\n -- Reading the Secret Key --- \n")
    path = pathlib.Path(base_dir + "/" + file_secret_key)

    # The secret_key will be read as BYTES: encoding is not necessary
    with open(path, 'rb') as file:
        secret_key_read = file.read()
        print_log(f"[read_secret_key] secret_key: {secret_key_read}\n")
    return secret_key_read


def write_log(log_filename: str, line: str) -> str:
    try:
        # The log_filename NEED now contain the full path
        # log_filename = os.path.join(os.getcwd(), filename)
        with open(log_filename, 'a') as f:
            # f.write(time.ctime() + line)
            # f.write(datetime.datetime.now().astimezone().replace(microsecond=0).isoformat() + line)
            # Local to ISO 8601 with TimeZone information (Python 3) - UTC to ISO 8601:
            f.write(datetime.datetime.utcnow().isoformat() + line)
    except OSError:
        print_log(f"File {log_filename} can not be found")


def handle_validating_of_request(token):
    """ Validating the token JWS provided by the request
    :param token: the token (JWS) received from UDP payload
    :return (payload|None,   dictionary of claims and a
            description|group_name)     description of ERROR or GROUP NAME
            payload,description or None,group_name
    """
    try:  # JWS: Decode and NOT check for signature
        algorithm = jwt.get_unverified_header(token).get('alg')
        if algorithm not in jwt_algorithms:
            return None, "Algorithm not supported"
        payload = jwt.decode(token, options={"verify_signature": False})

        # now = datetime.now(tz=timezone.utc).timestamp()
        now = int(datetime.datetime.utcnow().timestamp())
        if now > payload['exp']:
            return None, "Token expired"
        group_name = payload['sub']
        group_name = str(group_name.upper())
        print_log(f"[handle_validating_of_request] JWT decoded - type: {type(payload)}\n")
        print_log(f"[handle_validating_of_request] JWT decoded - content: {payload}\n")
        write_log(log_file_conn, f":{group_name}:{payload}:OK\n")
    except DecodeError:
        write_log(log_file_content, ":ERROR: Failed to decode: {e}\n")
        return None, "Decode failed"

    # We need the sub claim for search the public key of group
    try:
        group_name = payload['sub']
    except KeyError:
        return None, "No sub claim"

    # If we can decode, then we will use the information of group name to obtain the public key
    # Algorithms accepted: RS256 and ES256 (because we only have this type of public keys)
    #  JWS: Decode and CHECK SIGNATURE and IAT and EXP
    try:
        payload = jwt.decode(token, key=public_keys[group_name], algorithms=algorithm,
                             options={"verify_signature": True,
                                      "verify_aud": False,
                                      "verify_iss": False,
                                      "verify_nbf": False})
    except InvalidTokenError as e:
        write_log(log_file_content, f":{group_name}:NOTOK:ERROR:failed to decode:{e}\n")
        return None, "Signature validation failed"
    except InvalidSignatureError as e:
        write_log(log_file_content, f":{group_name}:NOTOK:ERROR:failed signature checked:{e}\n")
        return None, "Signature validation failed"
    except InvalidAlgorithmError as e:
        write_log(log_file_content, f":{group_name}:NOTOK:ERROR:error in algorithm:{e}\n")
        return None, "Signature validation failed"
    except InvalidKeyError as e:
        write_log(log_file_content, f":{group_name}:NOTOK:ERROR:problem in the keys:{e}\n")
        return None, "Signature validation failed"
    else:
        print_log(f"[Handle Request] JWT decoded and verified: {payload}\n")
        write_log(log_file_content, f":{group_name}:{payload}:Signature OK\n")
        return payload, group_name
    return None, ""


def handle_data_from_request(payload):
    """ Validating and checking the private claims from payload
    """
    group_name = payload['sub']
    if group_name not in GROUP_NAMES:
        return None, "Group name unknown"

    seq_number = payload['seq_state_number']

    if payload['seq_max'] != groups[group_name].num_members:
        return None, "The max number of members is wrong"
    if seq_number < STATE_MIN | seq_number > STATE_MAX:
        return None, "State number undefined"
    if payload['seq_state'] not in PROTOCOL_STATES:
        return None, "State not recognized"
    if payload['aud'] != jwt_audience:
        return None, "Audience (aud) not recognized"

    return payload, group_name


def generate_payload_for_response_with_error(description_of_error, group_name=None):
    """   This function generates the payload for ERROR response.
    :param group_name: the group name or None
    :param description_of_error: message of what error during validating (JWS and data)
    :return payload_for_response dictionary with basic claims
    :return (payload_for_response|None,   dictionary of claims for response
            group_name)                   group name
    """
    payload_for_response = {}
    if group_name is None:
        group_name = "NO_SUB_CLAIM"

    # JWT: registered claims
    payload_for_response['iss'] = "udp.socket.server.for.jwt"
    payload_for_response['sub'] = group_name
    payload_for_response["jti"] = secrets.token_hex(16)
    payload_for_response['iat'] = int(datetime.datetime.utcnow().timestamp())
    payload_for_response['exp'] = int(datetime.datetime.utcnow().timestamp()) + jwt_validity  # Validity: 30s

    # JWT: private claims
    # payload_for_response['id_request'] = hashlib.sha256(request_in_str.encode("utf-8")).hexdigest()
    payload_for_response['otp_timestamp'] = datetime.datetime.now().astimezone().isoformat()
    payload_for_response['response'] = "ERROR:" + description_of_error

    print_log(f"[Generate Payload for Response with ERROR] Payload for Response: {group_name}:{payload_for_response}")
    write_log(log_file_responses, f":{group_name}:{payload_for_response}\n")

    return payload_for_response, group_name


# This function generates the payload for VALID response.
# It will be signed by HMAC.
def generate_payload_for_response(id_request, group_name, next_number):
    payload_for_response = {}
    print_log(f"[Generate Payload for Response] Payload of Request: {group_name}:{next_number}:{id_request}\n")
    # JWT: registered claims
    payload_for_response['iss'] = "udp.socket.server.for.jwt"
    payload_for_response['sub'] = group_name
    payload_for_response["jti"] = secrets.token_hex(16)
    payload_for_response['iat'] = int(datetime.datetime.utcnow().timestamp())
    payload_for_response['exp'] = int(datetime.datetime.utcnow().timestamp()) + jwt_validity  # Validity: 30s

    # JWT: private claims
    # payload_for_response['id_request'] = hashlib.sha256(request_in_str.encode("utf-8")).hexdigest()
    payload_for_response['id_request'] = id_request
    payload_for_response['otp_timestamp'] = datetime.datetime.now().astimezone().isoformat()

    #  This is the claim for protocol FSM
    payload_for_response['next_number'] = next_number

    print_log(f"[Generate Payload for Response] Payload for Response: {group_name}:{payload_for_response}")
    write_log(log_file_responses, f":{group_name}:{payload_for_response}\n")

    return payload_for_response


def generate_token_jws(payload) -> str:
    """ Generate a token JWS signed with HMAC (password=secret_key)
    secret_key: the passphrase in BYTES (encoded)
    :param payload: JSON data contained the response
    :return token: JWT encoded and SIGNED with HMAC (with secret_key) | None in Exception
    """
    print_log(f"[Generate Token JWS for Response] Payload: {payload}\n")
    jwt_encoded = jwt.encode(payload=payload, key=secret_key, algorithm="HS256")
    print_log(f"[Generate Token JWS for Response] JWS: {jwt_encoded}\n")
    return jwt_encoded


def what_next_number(group_name, state_number, max_state):
    """ Protocol and states of this server (FSM: finite state machine):
    :param group_name: the name of the group: it was checked from the content of the request
    :param state_number: the number of the message ~ state (for ordening messages)
    :param max_states: what the number os states of this FSM protocol
    :return: the next_number that this server expects from the client; -1 for invalid state_number
    """
    if state_number < STATE_MIN | state_number > STATE_MAX:
        return -1

    actual_state = groups[group_name].get_last_n_received()

    # Case 0: restart the protocol
    if state_number == 0:
        groups[group_name].set_last_n_received(0)
        return 1

    # Case 1: client resent last information (the same state)
    if state_number == actual_state:
        next_number = state_number + 1
        # Case 3: arrived in final state: CHECK with max number contained in request
        groups[group_name].set_last_n_received(state_number)
        if state_number == max_state:
            next_number = 0
            # groups[group_name].set_last_n_received(max_states)
        return next_number

    # Case 2: client received OK and sending next number
    if state_number == actual_state + 1:
        next_number = state_number + 1
        groups[group_name].set_last_n_received(state_number)
        # Case 3: arrived in final state
        if state_number == max_state:
            next_number = 0
        return next_number

    # Default state: 0
    return 0


def handle_members_of_group(group_name, registration):
    write_log(log_file_registration_numbers, f":{group_name}:{registration}\n")
    print_log(f"[handle_members_of_group] {group_name}:{registration}\n")
    groups[group_name].add_member_registration(registration)


def handle_request(request):
    """ Entry point for handle the JWS token and for handle the
        protocol of messages.
        :param request JWS token
        :return (response|None,group_name)
    """

    # Decode and extract PAYLOAD from JWS: decode and check signature
    request_payload, message = handle_validating_of_request(request)

    # The message contains the message error
    if request_payload is None:
        print_log(f"[handle_request] ERROR in handle request: {request}\n")
        write_log(log_file_content, f":{request}\n")
        group_name = ""
        payload_for_response, group_mame = generate_payload_for_response_with_error(message)  # group_name=None
        response_token = generate_token_jws(payload_for_response)
        if response_token is None:
            return None, group_name
        else:
            return response_token, group_name

    # Check the data (private claims) provided by user
    result,message = handle_data_from_request(request_payload)
    if result is None:
        print_log(f"[handle_request] ERROR in handle request: {request_payload}\n")
        write_log(log_file_content, f":{request_payload}\n")
        payload_for_response = generate_payload_for_response_with_error(message)  # group_name=None
        group_name = ""
        response_token = generate_token_jws(payload_for_response)
        if response_token is None:
            return None, group_name
        else:
            return response_token, group_name

    # Check the number of the message from user (seq_state_number) and obtain the next number
    #    expected from the user

    group_name = request_payload['sub']
    max_number = STATE_MAX  # or    max_number = groups[group_name].get_number_members()
    next_number = what_next_number(group_name.upper(), int(request_payload['seq_state_number']), max_number)

    # Invalid seq_number sent by user
    if next_number < 0:
        return None, group_name

    handle_members_of_group(group_name, request_payload['registration'])
    request_in_str = str(request_payload)
    request_id = hashlib.sha256(request_in_str.encode("utf-8")).hexdigest()

    payload_for_response = generate_payload_for_response(request_id, group_name, next_number)
    write_log(log_file_responses, f":{group_name}:{payload_for_response}\n")
    print_log(f"[handle_request] group:{group_name} payload:{payload_for_response}\n")

    response_token = generate_token_jws(payload_for_response)
    print_log(f"[handle_request] group:{group_name} response:{response_token}\n")
    write_log(log_file_responses, f":{group_name}:{response_token}\n")

    if response_token is None:
        return None, group_name
    else:
        return response_token, group_name


def udp_server(server_addr, server_port, buffer):
    """ UDP socket server: point of interaction for the user
        This function set a server that receives and returns JWT"""
    try:
        server_sock = socket(AF_INET, SOCK_DGRAM)
    except OSError as e:
        server_sock = None
    try:
        server_sock.bind((server_addr, server_port))
    except OSError as e:
        server_sock.close()
        server_sock = None

    if server_sock is None:
        trace = traceback.format_exc()
        print_log(f"ERROR in socket creation: {trace}")
        open('trace.log', 'a').write(trace)
        sys.exit(1)

    print(f'[*] Listening on {server_addr}:{server_port}')

    try:
        while True:
            request_raw, client_addr = server_sock.recvfrom(buffer)
            print_log(f'[*] Accepted connection from {client_addr[0]}:{client_addr[1]}\n')
            print_log(f'[*] Received: {request_raw} - Received decoded: {request_raw.decode("utf-8")}\n')
            request = request_raw.decode('utf-8')
            write_log(log_file_conn, f':{client_addr[0]}:{client_addr[1]}:{request}\n')

            response,group_name = handle_request(request)

            # If we cannot create a JWS for response, we do not generate a UDP response
            if response is None:
                continue

            write_log(log_file_responses, f":{group_name}:{response}\n")
            print_log(f"[udp_server] Response: {group_name}:{response}\n")
            response_raw = response.encode('utf-8')
            print_log(f"[udp_server] Response Raw: {response_raw}\n")
            server_sock.sendto(response_raw, client_addr)


    except KeyboardInterrupt:
        trace = traceback.format_exc()
        print('Erro: ', trace)
        open('trace.log', 'a').write(trace)
        server_sock.close()
        raise SystemExit
    except UnicodeDecodeError as e:
        trace = traceback.format_exc()
        print('Erro: ', trace)
        open('trace.log', 'a').write(trace)
        #  server_sock.close()     # For testing, we leave system running
        #  raise SystemExit        # For testing, we leave system running
    except:
        trace = traceback.format_exc()
        print('Erro: ', trace)
        open('trace.log', 'a').write(trace)
        # server_sock.close()     # For testing, we leave system running
        # raise SystemExit        # For testing, we leave system running

    server_sock.close()


if __name__ == '__main__':

    # Some prefixed configurations
    base_dir = os.path.join(os.getcwd()) + "/"
    server_port = 44555
    server_addr = '0.0.0.0'
    buffer = 2048

    if base_dir is None and len(sys.argv) == 1:
        print(f"""\n ERROR in command. The program parameters: {sys.argv[0]} base_dir\n
          or\n
          $ {sys.argv[0]} local_address  local_port base_dir\n
          The parameter 'base_dir' contains all the files and the keys\n""")
    elif len(sys.argv) > 1:
        if len(sys.argv) == 2:
            server_addr = sys.argv[1]
            # socket.getaddrinfo("example.org", 80, proto=socket.IPPROTO_TCP)
        elif len(sys.argv) == 3:
            server_addr = sys.argv[1]
            server_port = int(sys.argv[2])
        elif len(sys.argv) == 4:
            server_addr = sys.argv[1]
            server_port = int(sys.argv[2])
            base_dir = sys.argv[3]

    # Full path specification
    log_file = base_dir + log_file  # "log-for-udpserver-jwt.txt"
    log_file_conn = base_dir + log_file_conn  # 'dec7557-log-connection_and_request.txt'
    log_file_content = base_dir + log_file_content  # 'dec7557-log-group_and_payload.txt'
    log_file_responses = base_dir + log_file_responses  # 'dec7557-log-group_and_responses.txt'
    log_file_sucess = base_dir + log_file_sucess  # 'dec7557-log-sucess.txt'
    log_response_pay = base_dir + log_response_pay  # "dec7557-response-payloads.txt"
    log_response_jwt = base_dir + log_response_jwt  # "dec7557-response-JWT.txt"
    log_file_registration_numbers = base_dir + log_file_registration_numbers # dec7557-log-group-registration-members.txt
    print_log(f"[main] log_file: {log_file}")
    print_log(f"[main] log_file_conn: {log_file_conn}")
    print_log(f"[main] log_file_content: {log_file_content}")
    print_log(f"[main] log_file_responses: {log_file_responses}")
    print_log(f"[main] log_file_sucess: {log_file_sucess}")
    print_log(f"[main] log_response_pay: {log_response_pay}")
    print_log(f"[main] log_response_jwt: {log_response_jwt}")
    print_log(f"[main] log_file_registration_numbers: {log_file_registration_numbers}")

    # Create the objects for all groups and read all the public keys (pubkey)
    #  The pubkey will be used to check signatures of JWS
    read_public_keys(base_dir)

    try:
        secret_key = read_secret_key(base_dir)
        if secret_key is None:
            write_log()
    except FileExistsError:
        trace = traceback.format_exc()
        print('ERROR - exiting: ', trace)
        open('trace.log', 'a').write(trace)
        sys.exit(1)

    while True:
        udp_server(server_addr, server_port, buffer)
