from django.contrib.auth import get_user_model, authenticate
from rest_framework import serializers
from .models import TeacherProfile

User = get_user_model()

# ------------------------------
# 1️⃣ USER SERIALIZER
# ------------------------------
# class UserSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = User
#         fields = ["id", "email", "first_name", "last_name", "role", "is_active"]
from rest_framework import serializers
from django.contrib.auth.models import User

from rest_framework import serializers
from .models import User  # Ensure correct import

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'username', 'first_name', 'last_name', 'role']

# ------------------------------
# 2️⃣ LOGIN SERIALIZER
# ------------------------------
from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import User  # Ensure you're importing your custom User model

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        user = authenticate(username=email, password=password)

        if user is None:
            raise serializers.ValidationError("Invalid email or password")  # Prevents NoneType error

        data["user"] = user
        return data

# ------------------------------
# 3️⃣ TEACHER REGISTRATION SERIALIZER
# ------------------------------
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import TeacherProfile  # Import TeacherProfile

from rest_framework import serializers
from django.contrib.auth.models import User
from .models import TeacherProfile

from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import TeacherProfile

User = get_user_model()  # Use dynamic user model

class TeacherRegistrationSerializer(serializers.ModelSerializer):
    subject = serializers.CharField(required=True)
    qualification = serializers.CharField(required=True)
    experience = serializers.IntegerField(required=True)
    contact_number = serializers.CharField(required=True)
    department = serializers.ChoiceField(choices=TeacherProfile.DEPARTMENT_CHOICES, required=True)
    profile_picture = serializers.ImageField(required=False)
    
    class Meta:
        model = User
        fields = ["username", "email", "password", "subject", "qualification", "experience", 
                 "contact_number", "department", "profile_picture"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        subject = validated_data.pop("subject")
        qualification = validated_data.pop("qualification")
        experience = validated_data.pop("experience")
        contact_number = validated_data.pop("contact_number")
        department = validated_data.pop("department")
        profile_picture = validated_data.pop("profile_picture", None)

        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
            role="teacher"
        )

        # Create the TeacherProfile
        TeacherProfile.objects.create(
            user=user,
            subject=subject,
            qualification=qualification,
            experience=experience,
            contact_number=contact_number,
            department=department,
            profile_picture=profile_picture,
            status="pending"
        )

        return user

# ------------------------------
# 4️⃣ TEACHER PROFILE SERIALIZER
# ------------------------------
class TeacherProfileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    email = serializers.EmailField(source='user.email', read_only=True)
    first_name = serializers.CharField(source='user.first_name', read_only=True)
    last_name = serializers.CharField(source='user.last_name', read_only=True)
    user_id = serializers.IntegerField(source='user.id', read_only=True)

    class Meta:
        model = TeacherProfile
        fields = ['id', 'user_id', 'username', 'email', 'first_name', 'last_name', 
                 'subject', 'qualification', 'experience', 'contact_number', 'status',
                 'department', 'profile_picture']
