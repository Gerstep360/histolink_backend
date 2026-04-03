"""
GestionDeUsuarios/LoginYAutenticacion/views.py

Vistas del sistema de autenticación de Histolink.
Todos los endpoints bajo /api/auth/.
"""

from rest_framework import generics, status
from rest_framework.exceptions import APIException
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from django.core.cache import caches

from .serializers import (
    RegisterSerializer,
    CustomTokenObtainPairSerializer,
    LogoutSerializer,
    ChangePasswordSerializer,
    UserSerializer,
)


def _bump_login_failure_count(cache, cache_key, timeout=60):
    """Incrementa intentos fallidos de forma atómica (evita condiciones de carrera)."""
    if not cache.add(cache_key, 1, timeout=timeout):
        cache.incr(cache_key)


# ── Registro ────────────────────────────────────────────────────────────

class RegisterView(generics.CreateAPIView):
    """
    POST /api/auth/register/

    Registra un nuevo usuario en auth_user.
    No requiere autenticación (AllowAny).

    Body:
        username, email, password, password_confirm
        first_name (optional), last_name (optional)

    Response 201:
        { message, user: { id, username, email, ... } }
    """
    serializer_class = RegisterSerializer
    permission_classes = (AllowAny,)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        user_data = UserSerializer(user).data
        return Response(
            {
                "message": "Usuario registrado exitosamente.",
                "user": user_data,
            },
            status=status.HTTP_201_CREATED,
        )


# ── Login (JWT con datos de usuario) ────────────────────────────────────

class CustomTokenObtainPairView(TokenObtainPairView):
    """
    POST /api/auth/login/

    Autenticación con username + password.
    Retorna access token, refresh token, y datos del usuario.

    Body:
        username, password

    Response 200:
        { access, refresh, user: { id, username, email, groups, ... } }
    """
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        # 1. Obtener la IP del request
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        ip = ip or "unknown"

        # 2. Construir la clave Redis
        cache_key = f"login_attempts:{ip}"
        cache = caches["rate_limit"]

        # 3. Consultar el contador
        attempts = cache.get(cache_key, 0) or 0

        # 4. Si el contador >= 10, retornar Response
        if attempts >= 10:
            return Response(
                {"detail": "Too many attempts"},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        try:
            response = super().post(request, *args, **kwargs)
        except APIException as exc:
            # SimpleJWT lanza AuthenticationFailed (401) por credenciales inválidas/inactivas.
            # No incrementar por ValidationError u otros 4xx (p. ej. body mal formado → 400).
            if exc.status_code == status.HTTP_401_UNAUTHORIZED:
                _bump_login_failure_count(cache, cache_key)
            raise

        if response.status_code == status.HTTP_200_OK:
            cache.delete(cache_key)

        return response



# ── Logout (Blacklist del Refresh Token) ────────────────────────────────

class LogoutView(APIView):
    """
    POST /api/auth/logout/

    Invalida el refresh token (lo agrega a token_blacklist_blacklistedtoken).
    El access token sigue válido hasta su expiración natural (15 min).

    Body:
        refresh (string — el refresh token JWT)

    Response 200:
        { message: "Sesión cerrada exitosamente." }
    """
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "Sesión cerrada exitosamente."},
            status=status.HTTP_200_OK,
        )


# ── Perfil del usuario autenticado ──────────────────────────────────────

class UserProfileView(APIView):
    """
    GET /api/auth/profile/

    Retorna el perfil del usuario autenticado.
    Requiere Bearer token en el header Authorization.

    Response 200:
        { id, username, email, first_name, last_name, is_active,
          is_staff, date_joined, last_login, groups: [...] }
    """
    permission_classes = (IsAuthenticated,)

    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# ── Cambio de Contraseña ────────────────────────────────────────────────

class ChangePasswordView(APIView):
    """
    PUT /api/auth/change-password/

    Cambia la contraseña del usuario autenticado.
    Requiere Bearer token.

    Body:
        old_password, new_password, new_password_confirm

    Response 200:
        { message: "Contraseña actualizada exitosamente." }
    """
    permission_classes = (IsAuthenticated,)

    def put(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={"request": request},
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "Contraseña actualizada exitosamente."},
            status=status.HTTP_200_OK,
        )
