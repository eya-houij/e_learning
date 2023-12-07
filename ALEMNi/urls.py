from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path("admin/", admin.site.urls),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path("student_portal/", include("student_portal.urls")),
    path("tutor_portal/", include("tutor_portal.urls")),
    path("administrator_dash", include("administrator_dash.urls")),
    path("API_module", include("API_module.urls")),
    path("analytics", include("analytics.urls")),
    path("course_management", include("course_management.urls")),
    path("authentification/", include("authentification.urls")),
    path("frontend", include("frontend.urls")),

    
]