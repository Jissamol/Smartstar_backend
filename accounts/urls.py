from django.urls import path
from .views import (
    TeacherRegistrationView, 
    AddStudent, LoginView, ProtectedView,
    pending_teachers, teacher_action,
    TeacherProfileView, StudentListView, StudentRegisterView
)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('protected/', ProtectedView.as_view(), name='protected'),
    path("teachers/pending/", pending_teachers, name="pending-teachers"),
    path("teachers/<int:teacher_id>/action/", teacher_action, name="teacher-action"),
    path('teachers/register/', TeacherRegistrationView.as_view(), name='teacher-register'),
    path("teacher/add-student/", AddStudent.as_view(), name="add-student"),
    path('teacher/profile/', TeacherProfileView.as_view(), name='teacher-profile'),
    path('students/department/<str:department>/', StudentListView.as_view(), name='student-list'),
    path('students/register/', StudentRegisterView.as_view(), name='student-register'),
]
