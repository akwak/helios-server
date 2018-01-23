# -*- coding: utf-8 -*-

from base64 import b64encode, b64decode

from django.core.urlresolvers import reverse
from django.http import HttpResponse

from helios.crypto.algs import EGCiphertext
from helios.views import one_election_cast_confirm as caster
import settings
from helios.crypto import elgamal
from helios.crypto import utils
from helios.crypto.elgamal import Plaintext
from helios import utils
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import json
from helios.workflows import homomorphic
import requests

from helios.security import election_view, HttpResponseRedirect
from helios_auth.security import save_in_session_across_logouts

ELGAMAL_PARAMS = elgamal.Cryptosystem()

# trying new ones from OlivierP
ELGAMAL_PARAMS.p = 16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071L
ELGAMAL_PARAMS.q = 61329566248342901292543872769978950870633559608669337131139375508370458778917L
ELGAMAL_PARAMS.g = 14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533L

keyholder = 'aaa'

RSAkey = RSA.generate(1024)


keypair = ELGAMAL_PARAMS.generate_keypair()
keyrand = 'Sixteen byte key'
signer = PKCS1_v1_5.new(RSAkey)

system_session_id = ''
user_session_id = ''

colors = ['red','blue','grey', 'yellow', 'green']
DATA_FILENAME = 'sessions_1'
VOTE_CODES_FILENAME='vote_codes'
# for test only
def home(request):
    return HttpResponse("home")

# unused
def encrypt(request):

    if request.method == 'POST':
        x = utils.from_json(request.body)
        hexkey = x[keyholder].encode('hex')
        m =  elgamal.Plaintext(int(hexkey,16))
        ciphertext = keypair.pk.encrypt(m)
        m_decrypt = keypair.sk.decrypt(ciphertext)
        hex_decrypt = bigint_to_string(m_decrypt)
        return HttpResponse(hex_decrypt)
    return HttpResponse("fail")



def perform_sign(request, session_id_holder):
    digest = SHA256.new()
    request_json = utils.from_json(request.body)
    session_id = (request_json[session_id_holder]).encode('utf-8')
    digest.update(session_id)
    digest.update(keyrand.encode('utf-8'))
    sign = signer.sign(digest)
    b64sign = b64encode(sign)
    json_dict = {'session_id': session_id, 'key_rand': keyrand, 'sign': b64sign}
    response_json = utils.to_json(json_dict)
    global system_session_id
    system_session_id = session_id;
    return response_json


# return signed with private key key and session id
def sign_with_private_key(request):
    session_id_holder = 'session_id'

    if request.method == 'POST':
        response_json = perform_sign(request, session_id_holder)
        return HttpResponse(response_json)
    return HttpResponse("not a post")

def sign_with_private_key_b64(request):
    session_id_holder = 'session_id'
    if request.method == 'POST':
        response = perform_sign(request, session_id_holder)
        return HttpResponse(b64encode(response))

def bigint_to_string(m_decrypt):
    hex_decrypt = hex(int(m_decrypt.m))
    hex_decrypt = hex_decrypt[2:]
    if hex_decrypt[-1] == 'L':
        hex_decrypt = hex_decrypt[:-1]
    return hex_decrypt.decode('hex')

def verify_signature(request):
    request_session_id_holder = 'session_id'
    request_key_holder = 'key_rand'
    request_sign_holder = 'sign'

    verifier = PKCS1_v1_5.new(RSAkey.publickey())
    digest = SHA256.new()

    request_json_body = utils.from_json(request.body)

    session_id = str(request_json_body[request_session_id_holder])
    key_rand_from_req = str(request_json_body[request_key_holder])
    request_sign = str(request_json_body[request_sign_holder])

    digest.update(session_id)
    digest.update(key_rand_from_req)

    request_sign = b64decode(request_sign)
    return HttpResponse(verifier.verify(digest,request_sign))



def get_public_key(request):
    exported_key = RSAkey.publickey().exportKey(format='DER')
    return HttpResponse(b64encode(exported_key))

def set_user_session_id(request):

    request_session_id_holder = 'session_id'
    election_id_holder = 'election_id'

    request_json_body = utils.from_json(request.body)
    json_user_session_id = str(request_json_body[request_session_id_holder])
    election_id = request_json_body[election_id_holder]

    session_dict = {}
    session_dict[request_session_id_holder] = json_user_session_id
    session_dict[election_id_holder] = election_id



    add_to_file(DATA_FILENAME, session_dict)


    global user_session_id
    user_session_id = json_user_session_id
    return HttpResponse("ok")


def add_to_file(DATA_FILENAME, entry):
    feeds = load_list(DATA_FILENAME)
    with open(DATA_FILENAME, mode='w') as f:
        json.dump([], f)
    with open(DATA_FILENAME, mode='w') as feedsjson:
        feeds.append(entry)
        json.dump(feeds, feedsjson)


def load_list(SESSIONS_FILENAME):
    with open(SESSIONS_FILENAME, mode='r') as feedsjson:
        feeds = json.load(feedsjson)
    return feeds


# def get_session_id(request):
#     global system_session_id
#     global user_session_id
#
#     if  'system_session_id' not in globals() and not 'user_session_id' in globals():
#         return HttpResponse("not defined yet")
#     return HttpResponse(system_session_id + user_session_id)

def get_session_id(request):
    requested_session_id = request.POST['session_id']
    sessions = load_list(DATA_FILENAME)

    full_session_string = ""
    election_id = ""
    for ses in sessions:
        if requested_session_id in ses['session_id']:
            full_session_string=ses['session_id']
            election_id = ses['election_id']
            break

    return HttpResponse(full_session_string + ';' + election_id)


#test now
def get_answer_tokens(request):
    response_dict = {}
    response_dict['colors'] = colors[:4]
    response_dict['codes'] =  ['XXX', 'AAA', 'XXY','23A']
    response_json = utils.to_json(response_dict)

    return HttpResponse(response_json)

@election_view()
def post_vote_codes(request, election):
    requested_session_id = request.POST['session_id']
    session_codes_json = request.POST['vote_codes']
    vote_codes = session_codes_json.split(';')

    entry = {}
    entry['session_id'] = requested_session_id
    entry['vote_codes'] = vote_codes

    add_to_file(VOTE_CODES_FILENAME, entry)
    return HttpResponse("ok")


def set_answer_amount(request):
    response_dict = {}
    response_dict['colors': colors[:4]]
    response_dict['codes': ['XXX', 'AAA', 'XXY','23A']]
    response_json = utils.to_json(response_dict)

    return HttpResponse(response_json)

@election_view()
def encrypt_ballot(request, election):
    encrypted_vote_json = request.POST['encrypted_vote']
    encrypted_vote = utils.from_json(encrypted_vote_json)

    #if hasattr(encrypted_vote, "session_id"):
    session_id = encrypted_vote['session_id']
    vote_codes_list = load_list(VOTE_CODES_FILENAME)
    vote_codes = []
    for vote_code_entry in vote_codes_list:
        if session_id == vote_code_entry['session_id']:
            vote_codes = vote_code_entry['vote_codes']
            break


    code_ciphertext_json = (encrypted_vote['answers'][0]['encrypted_code'])
    code_ciphertext = EGCiphertext()
    code_ciphertext.alpha = int(code_ciphertext_json['alpha'])
    code_ciphertext.beta = int(code_ciphertext_json['beta'])

    secret_key = None
    hex_decrypt = ""
    trustee = election.get_helios_trustee()
    if trustee is not None:
        secret_key = trustee.secret_key
        m_decrypt = secret_key.decrypt(code_ciphertext)
        hex_decrypt = bigint_to_string(m_decrypt)

    selected_answer = -1
    for i in range(len(vote_codes)):
        if vote_codes[i] == unicode(hex_decrypt):
            selected_answer = i

    if selected_answer == -1:
        return HttpResponse(request)

   # encrypted_answers =  (encrypted_vote['answers'])
    if selected_answer != -1:
        print 'good code'
        mocked_answers = [[selected_answer]]
        ev = homomorphic.EncryptedVote.fromElectionAndAnswers(election, mocked_answers)

    request.POST = request.POST.copy()
    json = unicode(ev.ld_object.serialize(), 'utf-8')
    request.POST['encrypted_vote'] = json
    save_in_session_across_logouts(request, 'encrypted_vote', json)
    return HttpResponseRedirect("%s%s" % (settings.SECURE_URL_HOST, reverse(caster, args=[election.uuid])))

def test_el_gamal_string_encryption(request):
    pass
