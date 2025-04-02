from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from .models import User, TeacherProfile, StudentProfile
from .permissions import IsAdminUser, IsTeacher, IsStudent
from .serializers import (
    UserSerializer, 
    TeacherProfileSerializer, 
    LoginSerializer,
    TeacherRegistrationSerializer,
    StudentProfileSerializer
)
import string
import random
from django.core.mail import send_mail
from django.conf import settings

# ADMIN VIEWS
class ViewTeacherRegistrations(APIView):
    permission_classes = [IsAdminUser]  # Add proper permissions
    
    def get(self, request):
        # Get all pending teacher profiles
        pending_teachers = TeacherProfile.objects.filter(status='pending')
        
        # Serialize the data
        serializer = TeacherProfileSerializer(pending_teachers, many=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)

class ApproveRejectTeacher(APIView):
    """Admin can approve/reject teacher registrations."""
    permission_classes = [IsAdminUser]

    def post(self, request, teacher_id):
        try:
            # Find the teacher profile
            teacher_profile = TeacherProfile.objects.get(id=teacher_id)
            action = request.data.get("action", "").lower()  # Ensure case consistency

            if action == "approve":
                teacher_profile.status = 'approved'
                # Also activate the user account
                user = teacher_profile.user
                user.is_active = True
                user.save()
                teacher_profile.save()
                return Response({"message": "Teacher approved successfully"}, status=status.HTTP_200_OK)

            elif action == "reject":
                teacher_profile.status = 'rejected'
                teacher_profile.save()
                # You might want to deactivate the user account too
                # teacher_profile.user.is_active = False
                # teacher_profile.user.save()
                return Response({"message": "Teacher rejected successfully"}, status=status.HTTP_200_OK)

            return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)

        except TeacherProfile.DoesNotExist:
            return Response({"error": "Teacher profile not found"}, status=status.HTTP_404_NOT_FOUND)

# TEACHER VIEWS
class AddStudent(APIView):
    """Teacher can add students."""
    permission_classes = [IsAuthenticated, IsTeacher]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(role="student", is_active=True)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# Generate JWT Tokens
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        try:
            user = User.objects.get(email=email)
            password_valid = user.check_password(password)
            if not password_valid:
                return Response({"error": "Password is incorrect"}, status=status.HTTP_400_BAD_REQUEST)

            # Generate tokens
            tokens = get_tokens_for_user(user)
            
            # Determine role (admin if superuser)
            role = 'admin' if user.is_superuser else user.role
            
            # Return tokens along with user info
            return Response({
                "success": True,
                "tokens": tokens,
                "user_info": {
                    "id": user.id,
                    "email": user.email,
                    "username": user.username,
                    "is_superuser": user.is_superuser,
                    "is_staff": user.is_staff,
                    "is_active": user.is_active,
                    "role": "admin" if user.is_superuser else user.role
                }
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response(
                {"error": "No user found with this email"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            print(f"Login error: {str(e)}")  # Add logging
            return Response(
                {"error": "An error occurred during login"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "You are authenticated", "user": UserSerializer(request.user).data})
    

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from .serializers import TeacherRegistrationSerializer

class TeacherRegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = TeacherRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Registration successful. Awaiting admin approval."},
                status=status.HTTP_201_CREATED
            )
        
        # Print errors to debug
        print("Validation Errors:", serializer.errors)  # Debugging line
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
from .models import TeacherProfile
from .permissions import IsAdminUser

@api_view(['POST'])
@permission_classes([IsAdminUser])
def teacher_action(request, teacher_id):
    """
    View to handle teacher approval/rejection
    """
    try:
        teacher_profile = TeacherProfile.objects.get(id=teacher_id)
        action = request.data.get('action', '')

        if action not in ['approve', 'reject']:
            return Response(
                {'error': 'Invalid action. Must be either "approve" or "reject".'}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        # Update teacher status based on action
        if action == 'approve':
            teacher_profile.status = 'approved'
        else:  # action == 'reject'
            teacher_profile.status = 'rejected'
        
        teacher_profile.save()

        return Response({
            'message': f'Teacher successfully {action}d',
            'teacher_id': teacher_id,
            'status': teacher_profile.status
        }, status=status.HTTP_200_OK)

    except TeacherProfile.DoesNotExist:
        return Response(
            {'error': f'Teacher with id {teacher_id} not found'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        print(f"Error in teacher_action: {str(e)}")  # Add logging for debugging
        return Response(
            {'error': 'An error occurred while processing your request'}, 
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import TeacherProfile
from .serializers import TeacherProfileSerializer

@api_view(["GET"])
@permission_classes([IsAuthenticated]) 
def pending_teachers(request):
    """
    Retrieves all teachers with status 'pending'.
    """
    teachers = TeacherProfile.objects.filter(user__role="teacher", status="pending")
    serializer = TeacherProfileSerializer(teachers, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

class ApproveRejectTeacherView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request, teacher_id):
        action = request.data.get('action')
        if action not in ['approve', 'reject']:
            return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            teacher_profile = TeacherProfile.objects.get(id=teacher_id)
            if action == 'approve':
                teacher_profile.status = 'approved'
                teacher_profile.user.is_active = True  # Activate the user account
                teacher_profile.user.save()
                message = "Teacher approved successfully."
            else:  # reject
                teacher_profile.status = 'rejected'
                message = "Teacher rejected successfully."

            teacher_profile.save()
            return Response({"message": message}, status=status.HTTP_200_OK)

        except TeacherProfile.DoesNotExist:
            return Response({"error": "Teacher profile not found"}, status=status.HTTP_404_NOT_FOUND)

class TeacherProfileView(APIView):
    permission_classes = [IsAuthenticated, IsTeacher]

    def get(self, request):
        try:
            teacher_profile = TeacherProfile.objects.get(user=request.user)
            if teacher_profile.status != 'approved':
                return Response(
                    {"error": "Your account is not approved yet"}, 
                    status=status.HTTP_403_FORBIDDEN
                )
            
            serializer = TeacherProfileSerializer(teacher_profile)
            user_serializer = UserSerializer(request.user)
            
            # Combine user and profile data
            data = {
                **user_serializer.data,
                **serializer.data
            }
            return Response(data, status=status.HTTP_200_OK)
            
        except TeacherProfile.DoesNotExist:
            return Response(
                {"error": "Teacher profile not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def put(self, request):
        try:
            teacher_profile = TeacherProfile.objects.get(user=request.user)
            if teacher_profile.status != 'approved':
                return Response(
                    {"error": "Your account is not approved yet"}, 
                    status=status.HTTP_403_FORBIDDEN
                )

            # Update user data
            user = request.user
            if 'username' in request.data:
                user.username = request.data['username']
            if 'email' in request.data:
                user.email = request.data['email']
            user.save()

            # Update teacher profile data
            if 'subject' in request.data:
                teacher_profile.subject = request.data['subject']
            if 'qualification' in request.data:
                teacher_profile.qualification = request.data['qualification']
            if 'experience' in request.data:
                teacher_profile.experience = request.data['experience']
            if 'contact_number' in request.data:
                teacher_profile.contact_number = request.data['contact_number']
            if 'department' in request.data:
                teacher_profile.department = request.data['department']
            if 'profile_picture' in request.FILES:
                teacher_profile.profile_picture = request.FILES['profile_picture']
            
            teacher_profile.save()

            # Return updated data
            serializer = TeacherProfileSerializer(teacher_profile)
            user_serializer = UserSerializer(user)
            data = {
                **user_serializer.data,
                **serializer.data
            }
            return Response(data, status=status.HTTP_200_OK)

        except TeacherProfile.DoesNotExist:
            return Response(
                {"error": "Teacher profile not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class AdminCheckView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        email = request.query_params.get('email')
        if not email:
            return Response({"error": "Please provide an email"}, status=status.HTTP_400_BAD_REQUEST)
            
        try:
            user = User.objects.get(email=email)
            return Response({
                "exists": True,
                "username": user.username,
                "is_active": user.is_active,
                "is_superuser": user.is_superuser,
                "is_staff": user.is_staff,
                "role": user.role
            })
        except User.DoesNotExist:
            return Response({"exists": False})

class TestLoginView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        if not email or not password:
            return Response({"error": "Both email and password are required"}, status=400)
            
        # Step 1: Check if user exists
        try:
            user = User.objects.get(email=email)
            user_exists = True
        except User.DoesNotExist:
            user_exists = False
            return Response({"error": "User does not exist"}, status=400)
            
        # Step 2: Check password if user exists
        if user_exists:
            password_valid = user.check_password(password)
            if not password_valid:
                return Response({"error": "Password is incorrect"}, status=400)
            
            # If we get here, both checks passed
            return Response({
                "success": True,
                "user_info": {
                    "email": user.email,
                    "is_superuser": user.is_superuser,
                    "is_staff": user.is_staff,
                    "is_active": user.is_active,
                    "role": user.role
                }
            })

class StudentListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, department):
        try:
            # Get the teacher's profile to verify department
            teacher_profile = TeacherProfile.objects.get(user=request.user)
            if teacher_profile.department != department:
                return Response(
                    {"error": "You can only view students in your department"},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Get all students in the department
            students = StudentProfile.objects.filter(department=department)
            serializer = StudentProfileSerializer(students, many=True)
            return Response(serializer.data)
        except TeacherProfile.DoesNotExist:
            return Response(
                {"error": "Teacher profile not found"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class StudentRegisterView(APIView):
    permission_classes = [IsAuthenticated]

    def generate_random_password(self, length=6):
        # Generate a random 6-digit password
        return ''.join(random.choice(string.digits) for _ in range(length))

    def post(self, request):
        try:
            # Get teacher's profile and department
            teacher_profile = TeacherProfile.objects.get(user=request.user)
            if not teacher_profile.status == 'approved':
                return Response({'error': 'Only approved teachers can add students'}, status=status.HTTP_403_FORBIDDEN)

            # Validate department matches teacher's department
            department = request.data.get('department')
            if not department:
                return Response({'error': 'Department is required'}, status=status.HTTP_400_BAD_REQUEST)
            
            if department != teacher_profile.department:
                return Response({'error': 'You can only add students to your own department'}, status=status.HTTP_403_FORBIDDEN)

            # Check if email already exists
            email = request.data.get('email')
            if User.objects.filter(email=email).exists():
                return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

            # Check if username already exists
            username = request.data.get('username')
            if User.objects.filter(username=username).exists():
                return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)

            # Check if roll number already exists
            roll_number = request.data.get('roll_number')
            if StudentProfile.objects.filter(roll_number=roll_number).exists():
                return Response({'error': 'Roll number already exists'}, status=status.HTTP_400_BAD_REQUEST)

            # Generate random password (6 digits)
            password = self.generate_random_password()

            # Create user
            user_data = {
                'username': username,
                'email': email,
                'password': password,
                'role': 'student'
            }
            user = User.objects.create_user(**user_data)

            # Create student profile
            student_profile = StudentProfile.objects.create(
                user=user,
                department=department,
                roll_number=roll_number,
                semester=request.data.get('semester')
            )

            # Send email with credentials
            try:
                subject = 'Your SmartStar Account Credentials'
                message = f'''
                Welcome to SmartStar!
                
                Your account has been created by your teacher.
                
                Username: {username}
                Password: {password}
                
                Please login and change your password immediately.
                
                Best regards,
                SmartStar Team
                '''
                from_email = settings.EMAIL_HOST_USER
                recipient_list = [email]
                
                # Print debug information
                print(f"Attempting to send email to: {email}")
                print(f"From email: {from_email}")
                print(f"Subject: {subject}")
                
                send_mail(
                    subject,
                    message,
                    from_email,
                    recipient_list,
                    fail_silently=False,
                )
                print("Email sent successfully!")
            except Exception as e:
                print(f"Failed to send email: {str(e)}")
                # Log the error but don't fail the registration
                import traceback
                traceback.print_exc()

            return Response({
                'message': 'Student registered successfully. Credentials have been sent to their email.',
                'student_id': student_profile.id
            }, status=status.HTTP_201_CREATED)

        except TeacherProfile.DoesNotExist:
            return Response({'error': 'Teacher profile not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
