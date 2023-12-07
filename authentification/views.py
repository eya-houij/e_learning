from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAuthenticatedOrReadOnly, BasePermission
from django.contrib.auth.tokens import default_token_generator
from django.contrib import messages
from django.shortcuts import redirect
from django.utils.http import urlsafe_base64_decode

import student_portal
import tutor_portal
from .serializers import RegisterSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.decorators import login_required
from .models import CustomUser as User


class IsNotAuthenticated(BasePermission):
    def has_permission(self, request, view):
        return not request.user.is_authenticated


class LoginAPI(APIView):
    permission_classes = [IsNotAuthenticated]  # Allow unauthenticated access for login

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = authenticate(username=username, password=password)

        if user:
            refresh = RefreshToken.for_user(user)

            # Perform redirection after successful login
            redirection_target = redirect_based_on_role(user.role)
            return Response({
                'user_info': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                },
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'redirect_to': redirection_target  # Include redirection target in response
            })
        else:
            return Response({'detail': 'Invalid credentials'}, status=400)


class IsTutorOrAdmin(BasePermission):
    def has_permission(self, request, view):
        # Allow access if user is authenticated and is either a Tutor or an Administrator
        return request.user.is_authenticated and (request.user.role == 'TUTOR' or request.user.role == 'ADMINISTRATOR')

class UserDataView(APIView):
    permission_classes = [IsTutorOrAdmin]  # Requires authenticated user to be a Tutor or an Administrator

    def get(self, request):
        #we used request.user so that the informations of the curent user display(the authenticated user(logged in))
        user = request.user 
        return Response({
            'user_info': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        })




class RegisterAPI(APIView):
    permission_classes = [IsNotAuthenticated]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        cuser = serializer.save()
        return Response({
            'user_info': {
                'id': cuser.id,
                'username': cuser.username,
                'email': cuser.email,
                'role': cuser.role,
            },
            'access_token': cuser['access'],
            'refresh_token': cuser['refresh']
        })



class CanConfirmEmail(BasePermission):
    def has_permission(self, request, view):
        # Allow access only for unconfirmed users
        return not request.user.is_authenticated or not request.user.email_confirmed


class EmailConfirmationView(APIView):
    permission_classes = [CanConfirmEmail]  # Allow access for unconfirmed users
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)

            if default_token_generator.check_token(user, token):
                user.email_confirmed = True
                user.save()
                messages.success(request, 'Email confirmed successfully!')
            else:
                messages.error(request, 'Invalid token. Please try again.')
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            messages.error(request, 'Invalid user. Please try again.')

        return redirect('home')


def redirect_based_on_role(role):
    if role == 'STUDENT':
        return redirect('student_courses')  # Redirects to the 'student_courses' URL pattern
    elif role == 'TUTOR':
        return redirect('tutor_courses')  
    elif role == 'ADMINISTRATOR':
        return redirect('administrator_dash') 
    else:
        return redirect('register')  



