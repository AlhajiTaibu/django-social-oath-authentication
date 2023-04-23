from rest_framework import exceptions
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from .models import User


class InputSerializer(serializers.Serializer):
    code = serializers.CharField(required=False)
    error = serializers.CharField(required=False)


class RegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["email", "username", "password"]
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        if len(attrs["password"]) < 8:
            raise serializers.ValidationError({
                "error": "passwords should be more than 8 characters"
            })
        return super().validate(attrs)

    def create(self, validated_data):
        print(validated_data)
        return User.objects.create_user(**validated_data)


class UserAuthenticationSerializer(TokenObtainPairSerializer):
    class Meta:
        model = User

    def validate(self, attrs):
        # attrs[self.username_field] = self.get_username_field_value(attrs)
        try:
            user = User.objects.get(email=attrs['email'])
        except User.DoesNotExist:
            raise exceptions.AuthenticationFailed(
                self.error_messages['no_active_account'],
                'no_active_account',
            )

        if not user.is_active:
            error_message = "User account is deactivated"
            error_name = "deactivated_account"
            raise exceptions.AuthenticationFailed(error_message, error_name)

        data = super().validate(attrs)

        if not self.user.is_activated:
            raise exceptions.AuthenticationFailed('Account not activated. '
                                                  'Kindly verify your account by entering the 4-digit code in your '
                                                  'mail or SMS inbox. '
                                                  )
        if not self.user.is_active:
            raise exceptions.AuthenticationFailed('Account is deactivated')

        return data
