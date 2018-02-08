# -*- coding: utf-8 -*-

from base64 import b64encode, b64decode

from django.core.urlresolvers import reverse
from django.http import HttpResponse

from helios.crypto.algs import EGCiphertext, EGZKDisjunctiveProof, EGZKProof
from helios.crypto.electionalgs import DLogTable
from helios.models import BallotAssistance, Election
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

colors = ['red','blue','grey', 'green', 'purple', 'brown']
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

    old_session=request_json_body['generated_session_id']


    vote_session = BallotAssistance.get_by_session(session=old_session)
    vote_session.session = json_user_session_id
    vote_session.save()

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



def get_session_id(request):
    requested_session_id = request.POST['session_id']


    vote_session = BallotAssistance.get_by_qr_session(requested_session_id)

    return HttpResponse(vote_session.session + ';' + vote_session.election.uuid)


#test now
@election_view()
def get_answer_tokens(request,election):
    question = election.questions[0]

    response_dict = {}
    response_dict['colors'] = colors[:len(question['answers'])]
    response_json = utils.to_json(response_dict)

    return HttpResponse(response_json)

@election_view()
def post_vote_codes(request, election):
    requested_session_id = request.POST['session_id']
    session_codes_json = request.POST['vote_codes']

    session_vote = BallotAssistance.get_by_election_and_session(election=election, session=requested_session_id)
    session_vote.cast_codes = session_codes_json
    session_vote.save()

    #add_to_file(VOTE_CODES_FILENAME, entry)
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

    vote_session = BallotAssistance.get_by_election_and_session(election=election,session=session_id)

    vote_codes = []
    if vote_session.cast_codes is not None:
        vote_codes = vote_session.cast_codes.split(';')

    answer_code_ciphertext = parse_ciphertext(encrypted_vote['answers'][0]['encrypted_code'], election.public_key)


    permutation_ciphertexts = []
    for json_ciphertext in encrypted_vote['answers'][0]['encrypted_permutation']:
        permutation_ciphertexts.append(parse_ciphertext(json_ciphertext))

    decrypted_permutation = []

    secret_key = None
    hex_decrypt = ""
    trustee = election.get_helios_trustee()
    if trustee is not None:

        dlog_table = DLogTable(base=trustee.public_key.g, modulus=trustee.public_key.p)
        dlog_table.precompute(len(permutation_ciphertexts))

        secret_key = trustee.secret_key
        m_decrypt = secret_key.decrypt(answer_code_ciphertext)
        hex_decrypt = bigint_to_string(m_decrypt)

        verify_proof = (answer_code_ciphertext.verify_encryption_proof(m_decrypt, EGZKProof.from_dict(encrypted_vote['answers'][0]['code_proof'])))
        print(verify_proof)



        for cipher in permutation_ciphertexts:
            raw_value = secret_key.decrypt(cipher)
            decrypted_permutation.append(dlog_table.lookup(raw_value.m))



    selected_answer = -1
    #map first_bijection
    selected_answer = vote_codes.index(unicode(hex_decrypt))
    selected_answer = decrypted_permutation.index(selected_answer)

    # for i in range(len(vote_codes)):
    #     if vote_codes[i] == unicode(hex_decrypt):
    #         selected_answer = i

    if selected_answer == -1 or selected_answer > len(decrypted_permutation):
        return HttpResponse(request)

   # encrypted_answers =  (encrypted_vote['answers'])
    if selected_answer != -1:
        print 'good code'
        mocked_answers = [[selected_answer]]
        ev = homomorphic.EncryptedVote.fromElectionAndAnswers(election, mocked_answers)
        vote_session.vote_code = unicode(hex_decrypt)
        vote_session.save()

    request.POST = request.POST.copy()
    json = unicode(ev.ld_object.serialize(), 'utf-8')
    request.POST['encrypted_vote'] = json
    save_in_session_across_logouts(request, 'encrypted_vote', json)
    return HttpResponseRedirect("%s%s" % (settings.SECURE_URL_HOST, reverse(caster, args=[election.uuid])))


def parse_ciphertext(code_ciphertext_json, pk=None):
    code_ciphertext = EGCiphertext.from_dict(code_ciphertext_json, pk)
    return code_ciphertext


def test_el_gamal_string_encryption(request):
    pass

@election_view()
def create_session_vote(request, election):
    if request.method != "POST":
        pass

    session_json = utils.from_json(request.body)
    if session_json is None:
        pass

    session_id = session_json['session_json']

    vote_session = BallotAssistance(session = session_id, election = election, qr_session = session_id)
    vote_session.save()
    return HttpResponse("ok")


    pass

@election_view()
def check_vote_code(request, election):
    if request.method != "POST":
        pass

    session_id = request.POST['session_id']

    vote_session = BallotAssistance.get_by_election_and_session(session = session_id, election = election)
    if vote_session.vote_code is not None:
        return HttpResponse(vote_session.vote_code)
    else:
        return HttpResponse("NONE")

@election_view()
def audit_ballot_election(request, election):
    session_id = request.POST['session_id']
    answers_json = utils.from_json(request.POST['answers_json'])
    selected_vote_code = answers_json['answers'][0]['code_choice']
    permutation = answers_json['answers'][0]['permutation']
    vote_session = BallotAssistance.get_by_election_and_session(session=session_id, election=election)
    vote_session.vote_code=selected_vote_code
    vote_session.save()
    vote_codes = vote_session.cast_codes.split(';')
    json_vote = utils.to_json(vote_codes)
    return HttpResponse(json_vote)