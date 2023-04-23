from urllib.parse import urlencode

import requests
from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from dj_rest_auth.registration.views import SocialLoginView
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.http import HttpResponse
from django.shortcuts import redirect
from django.shortcuts import render
from django.template.loader import get_template
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import generics
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_jwt.compat import set_cookie_with_token
from rest_framework_jwt.settings import api_settings
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import User
from .script import create_message, send_message, create_message_with_attachment
from .serializers import RegistrationSerializer, InputSerializer, UserAuthenticationSerializer
from .service import google_get_access_token, google_get_user_info, google_get_user_id, facebook_get_access_token, facebook_get_user_info


class Authentication(TokenObtainPairView):
    serializer_class = UserAuthenticationSerializer

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class RegistrationView(generics.CreateAPIView):
    serializer_class = RegistrationSerializer

    def _send_email_verification(self, user: User):
        current_site = get_current_site(self.request)
        subject = 'Activate Your Account'
        body = render_to_string(
            './email_verification.html',
            {
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': email_verification_token.make_token(user),
            }
        )

        try:
            user_id = 'me'
            receiver = user.email
            msg = create_message('me', receiver, subject, body)
            send_message(user_id, msg)
            return {'message': 'Email sent'}
        except Exception as error:
            return {'message': f"Email not sent {error}"}

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        user = User.objects.get(email=serializer.validated_data.get('email'))
        data = self._send_email_verification(user)
        headers = self.get_success_headers(serializer.data)
        return Response(data, status=status.HTTP_201_CREATED, headers=headers)


def jwt_login(*, response: HttpResponse, user: User) -> HttpResponse:
    jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
    jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER

    payload = jwt_payload_handler(user)
    token = jwt_encode_handler(payload)

    if api_settings.JWT_AUTH_COOKIE:
        set_cookie_with_token(response, api_settings.JWT_AUTH_COOKIE, token)

    return response


class GoogleLogin(SocialLoginView):
    class GoogleAdapter(GoogleOAuth2Adapter):
        access_token_url = "https://oauth2.googleapis.com/token"
        authorize_url = "https://accounts.google.com/o/oauth2/v2/auth"
        profile_url = "https://www.googleapis.com/oauth2/v2/userinfo"

    adapter_class = GoogleAdapter
    client_class = OAuth2Client
    serializer_class = InputSerializer

    def get(self, request, *args, **kwargs):
        input_serializer = self.serializer_class(data=request.GET)
        input_serializer.is_valid(raise_exception=True)

        validated_data = input_serializer.validated_data

        code = validated_data.get('code')
        error = validated_data.get('error')

        login_url = f'{settings.BASE_BACKEND_URL}'

        if error or not code:
            params = urlencode({'error': error})
            return redirect(f'{login_url}?{params}')

        domain = settings.BASE_BACKEND_URL
        api_uri = reverse('google_login')
        redirect_uri = f'{domain}{api_uri}'
        access_token = google_get_access_token(code=code, redirect_uri=redirect_uri)
        user_data = google_get_user_info(access_token=access_token['access_token'])
        user_id = google_get_user_id(id_token=access_token['id_token'])
        email = user_data.get('email')
        if not email:
            email = f"{user_id}@mail.com"
        try:
            user = User.objects.get(username=user_data['name'])
        except User.DoesNotExist:
            user = User.objects.create_user(username=user_data['name'], email=email)
        response = redirect("http://localhost:8000/account/lol")
        response = jwt_login(response=response, user=user)
        return response


def index(request):
    try:
        user_id = 'me'
        raw_mail_body = get_template(
            'homie.html'
        )
        mail = raw_mail_body.render()
        receiver = 'abdurami.taibu@gmail.com'
        msg = create_message_with_attachment('me', receiver,
                                             'PingGo Email Demo', mail, './chelsea-home-stadium-shirt.jpeg')
        send_message(user_id, msg)
        return render(request, 'success.html', {'receiver': receiver})

    except Exception as error:
        return render(request, 'error.html', {'error': error})


def lol(request):
    return render(request, 'lol.html')


def profile(request):
    print(f"hello: {request.body, request.user}")
    return render(request, 'homie.html', {'user': request.user})


class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
                str(user.is_active) + str(user.pk) + str(timestamp)
        )


email_verification_token = EmailVerificationTokenGenerator()


class ActivateView(APIView):

    def get_user_from_email_verification_token(self, uuid, token: str):
        try:
            uid = force_str(urlsafe_base64_decode(uuid))
            uid = int(uid)
            user = User.objects.get(pk=uid)
        except Exception as error:
            print(f"error: {error}")
            return None
        if user is not None and email_verification_token.check_token(user, token):
            return user

        return None

    def get(self, request, uidb64, token):
        user = self.get_user_from_email_verification_token(uidb64, token)
        user.is_active = True
        user.is_activated = True
        user.save()
        return redirect("http://localhost:8000/account/lol")


def facebook_login(request):
    redirect_uri = "%s://%s%s" % (
        request.scheme, request.get_host(), reverse('facebook_login')
    )

    if 'code' in request.GET:

        code = request.GET.get('code')
        data = facebook_get_access_token(code=code,redirect_uri=redirect_uri)
        user_data = facebook_get_user_info(params=data)
        print(f"hello: {user_data}")
        user_id = user_data.get('id')
        email = user_data.get('email')

        if not email:
            email = f"{user_id}@gmail.com"

        name = user_data.get('name')
        if email and name:
            user, _ = User.objects.get_or_create(email=email, username=name)
            return redirect("http://localhost:8000/account/lol")
        else:
            messages.error(
                request,
                'Unable to login with Facebook Please try again'
            )
        return redirect('/')

    else:
        url = "https://graph.facebook.com/oauth/authorize"
        params = {
            'client_id': settings.FB_APP_ID,
            'redirect_uri': redirect_uri,
            'scope': 'email,public_profile,user_birthday'
        }
        url += '?' + urlencode(params)
        return redirect(url)
