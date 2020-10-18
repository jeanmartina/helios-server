# -*- coding: utf-8 -*-
"""
Digital Certification Authentication
Author : jean.martina@gmail.com
Version: 1.0
Requirements: Need to add the following to default-ssl.conf for Apache

SSLCACertificateFile /home/votacao/CA.pem
SSLProtocol TLSv1.2
<Location /auth/cert/login>
 SSLVerifyDepth  10
 SSLOptions +StdEnvVars +ExportCertData +OptRenegotiate
 SSLVerifyClient require
</Location>

Description: 
This module works with digital certificates issued by ICP-Brasil or ICPEDU in Brazil 
for enabling voters to authenticate with digital certificates only. We trust Apache
for establishing a mutual SSL authentication and validating the certificate. Once Apache
authenticates the user we access the variable SSL_CLIENT_CERT which contains the PEM
encoded digital certificate for the user, which was already validated by Apache against
SSLCACertificateFile trusted certification authorities. We are requiring TLSv1.2 beacuse 
TLSv1.3 has issues with some browsers when switching client verification context.

The module extracts the relevant data for creating the user from the digital certificate
following ICP-Brasil regulations. The userid comes from CPF which is always embedded on
SAN with the extension oid 2.16.76.1.3.1 at a specific position. Email comes from SAN at
RFC822Name extension, using the first e-mail present. Name comes from the certificate CN 
field being sanitized to trail what comes fater the semicolon.

To put it to work you need to enable 'cert' on your authentication systems and pay 
attention to AUTH_BIND_USERID_TO_VOTERID, which should also be 'cert' when running
restricted elections.

TODO: 
Cleanup the code regarding some LDAP things that were left behind.
Create variables to configure the module through settings.py.
Test and adapt it with ngnix.
Test against CNPJ certificates, since it will get the name of the company instead of the 
the name of the voter whose CPF is the user id.
Cretae script to automaticaly cretae and update CA.pem.
Enable the use of CLRs and its updates.
Enable the use of OCSP for digital certificates that use this feature.

TIP:
CA.pem can be automatically generated and updated for ICP-Brasil  with the scritp avaliable at
https://gist.github.com/skarllot/9663935

It is important to mention that this module is heavely based on the LDAP module present at
https://github.com/ifsc/helios-server

"""

from django import forms
from django.conf import settings
from django.conf.urls import url
from django.core.mail import send_mail
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.oid import NameOID

# some parameters to indicate that status updating is possible
STATUS_UPDATES = False

LDAP_LOGIN_URL_NAME = "auth@cert@login"
LOGIN_MESSAGE = _("Log in with my Digital Certificate")


def cert_login_view(request):
    from helios_auth.view_utils import render_template
    from helios_auth.views import after

    error = None

    request.session['auth_system_name'] = 'cert'

    if request.POST.has_key('return_url'):
        request.session['auth_return_url'] = request.POST.get('return_url')

    authentication_status = request.META.get('SSL_CLIENT_VERIFY', None)
    if (authentication_status != "SUCCESS"):
        error = _("Bad Digital Certificate Authentication")
    else:    
        cert = x509.load_pem_x509_certificate(request.META.get('SSL_CLIENT_CERT', None),default_backend())
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_dados_pf = None
        for e in ext.value:
           if isinstance(e,x509.OtherName):
            if (e.type_id == x509.ObjectIdentifier("2.16.76.1.3.1")):
                san_dados_pf = e.value
        dn_san_dado_pf = san_dados_pf[2:10]
        cpf_san_dado_pf = san_dados_pf[10:21]
        email_san_rfc822name = ext.value.get_values_for_type(x509.RFC822Name)[0]
        cn_cer = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.split(':')[0]
        print(dn_san_dado_pf, cpf_san_dado_pf, email_san_rfc822name, cn_cer)
        request.session['cert_user']  = {
            'username': cpf_san_dado_pf,
            'email': email_san_rfc822name,
            'name': cn_cer,
        }
        return HttpResponseRedirect(reverse(after))

    return render_template(request, 'certauth/login', {
            'error': error,
            'enabled_auth_systems': settings.AUTH_ENABLED_AUTH_SYSTEMS,
        })


def get_user_info_after_auth(request):
    return {
       'type': 'cert',
       'user_id' : request.session['cert_user']['username'],
       'name': request.session['cert_user']['name'],
       'info': {'email': request.session['cert_user']['email']},
       'token': None
    }


def get_auth_url(request, redirect_url = None):
    return reverse(cert_login_view)


def send_message(user_id, name, user_info, subject, body):
    send_mail(subject, body, settings.SERVER_EMAIL, ["%s <%s>" % (name, user_info['email'])],
            fail_silently=False, html_message=body)


def check_constraint(constraint, user_info):
    """
    for eligibility
    """
    pass


def can_create_election(user_id, user_info):
  return True

urlpatterns = [url(r'^cert/login', cert_login_view, name=LDAP_LOGIN_URL_NAME)]
