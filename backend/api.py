from rest_framework import viewsets, permissions, generics
from rest_framework.response import Response
from knox.models import AuthToken
from .serializers import CreateUserSerializer, UserSerializer, LoginUserSerializer
from django.http import JsonResponse


class RegistrationAPI(generics.GenericAPIView):
    serializer_class = CreateUserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "user": UserSerializer(user, context=self.get_serializer_context()).data,
            "token": AuthToken.objects.create(user)[1]
        })



from django.contrib.auth.models import User

from rest_framework import serializers
from django.contrib.auth import authenticate
from django.utils.translation import gettext_lazy as _
from knox.views import LoginView as KnoxLoginView
from django.contrib.auth import login


class MyAuthTokenSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        label=_("Password"),
        style={'input_type': 'password'},
        trim_whitespace=False,
        write_only=True
    )
    token = serializers.CharField(
        label=_("Token"),
        read_only=True
    )

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        try:
            username = User.objects.get(email=email).username
        except Exception as e:
            print('#'*50, e)
            msg = _('Error Username')
            raise serializers.ValidationError(msg, code='authorization')

        if email and password:
            user = authenticate(request=self.context.get('request'),
                                username=username, password=password)

            # The authenticate call simply returns None for is_active=False
            # users. (Assuming the default ModelBackend authentication
            # backend.)
            if not user:
                msg = _('Error Password')
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg, code='authorization')
            # ][;
        attrs['user'] = user
        return attrs


class LoginAPI(KnoxLoginView):
    permission_classes = (permissions.AllowAny,)

    def post(self, request, format=None):
        serializer = MyAuthTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        login(request, user)
        return super(LoginAPI, self).post(request, format=None)

# class LoginAPI(generics.GenericAPIView):
#     serializer_class = LoginUserSerializer
#
#     def post(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         user = serializer.validated_data
#         return Response({
#             "user": UserSerializer(user, context=self.get_serializer_context()).data,
#             "token": AuthToken.objects.create(user)[1]
#         })

class UserAPI(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated, ]
    serializer_class = UserSerializer

    def get_object(self):
        return self.request.user

from rest_framework.decorators import api_view,permission_classes
from rest_framework.permissions import IsAuthenticated

@api_view(['POST'])
@permission_classes((IsAuthenticated, ))
def change_password(request):
    try:
        user = User.objects.get(pk=request.user.id)
    except :
        return JsonResponse({'status': "User Not Found 404"})
    try:
        old_password = request.POST['old_password']
        new_password = request.POST['new_password']
        confirm_new_password = request.POST['confirm_new_password']
    except:
        msg = _('يرجى التأكد من إدخال جميع الحقول.')
        raise serializers.ValidationError(msg, code='authorization')

    if not user.check_password(old_password):
        msg = _('كلمة المرور القديمة المدخلة غير صحيحة')
        raise serializers.ValidationError(msg, code='authorization')
    elif new_password != confirm_new_password :
        msg = _('كلمات المرور المدخلة غير متطابقة.')
        raise serializers.ValidationError(msg, code='authorization')
    if len(new_password) < 8 :
        msg = _('كلمة المرور قصيرة جدا ، يجب أن لا تقل كلمة المرور عن 8 حروف أو أرقام.')
        raise serializers.ValidationError(msg, code='authorization')
    elif old_password == new_password :
        msg = _('كلمة المرور القديمة لا يمكن أن تكون هي كلمة المرور الجديدة، يرجى إختيار كلمة أخرى.')
        raise serializers.ValidationError(msg, code='authorization')
    else :
        user.set_password(new_password)
        user.save()
        # update_session_auth_hash(request, user)
        return JsonResponse({'status': "تم تغيير كلمة المرور بنجاح"})
