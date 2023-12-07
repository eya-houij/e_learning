from django.urls import include, path

import student_portal
from student_portal.views import course_list 
import tutor_portal
from tutor_portal.views import CourseListCreateView
from .views import LoginAPI, RegisterAPI, UserDataView

urlpatterns = [
    path('login/', LoginAPI.as_view(), name='login'),  
    path('register/', RegisterAPI.as_view(), name='register'),  
    path('user/', UserDataView.as_view(), name='user'), 
    path('student/', include(student_portal.urls)),
    path('tutor/', include(tutor_portal.urls)),
    path('tutor-portal/courses/', CourseListCreateView.as_view(), name='tutor_courses'),
    path('student-portal/courses/', course_list, name='student_courses'),

]
