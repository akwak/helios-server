from django.conf.urls import *


from views import *





urlpatterns = patterns('',
  (r'^$', home),
                       (r'^sign_b64$', sign_with_private_key_b64),
                       (r'^get_public_key$', get_public_key),
  #test only
  (r'^sign$', sign_with_private_key),
  (r'^test_verify$', verify_signature),
                       (r'^set_user_session_id$', set_user_session_id),
                       (r'^get_session_id$', get_session_id),
                       #(r'^get_answer_tokens', get_answer_tokens),
                       (r'^set_answer_amount', set_answer_amount),

                       (r'elections/(?P<election_uuid>[^/]+)/create_session', create_session_vote),
                       (r'elections/(?P<election_uuid>[^/]+)/encrypt-ballot', encrypt_ballot),
                       (r'elections/(?P<election_uuid>[^/]+)/post_vote_codes', post_vote_codes),
                       (r'elections/(?P<election_uuid>[^/]+)/check_vote_code', check_vote_code),
                        (r'elections/(?P<election_uuid>[^/]+)/get_answer_tokens', get_answer_tokens),
                        (r'elections/(?P<election_uuid>[^/]+)/audit_ballot_election', audit_ballot_election),
                       # (r'^decrypt$', decrypt),
                       (r'encrypt', encrypt)

)
