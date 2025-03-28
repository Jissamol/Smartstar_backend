from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models

# Custom User Manager
class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        """Creates and returns a regular user."""
        if not email:
            raise ValueError("Users must have an email address")
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        """Creates and returns a superuser with admin permissions."""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("role", "admin")  # Explicitly set role to "admin"

        return self.create_user(username, email, password, **extra_fields)

# Custom User Model
class User(AbstractUser):
    ROLES = (
        ('admin', 'Admin'),
        ('teacher', 'Teacher'),
        ('student', 'Student'),
    )

    email = models.EmailField(unique=True)
    role = models.CharField(max_length=10, choices=ROLES, default='student')
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    is_active = models.BooleanField(default=True)

    objects = UserManager()  # Ensure the correct manager is used

    USERNAME_FIELD = 'email'  # Use email as the login field
    REQUIRED_FIELDS = ['username']  # This keeps `createsuperuser` working

    def __str__(self):
        return f"{self.username} ({self.role})"

# Teacher Profile (Linked to User)
class TeacherProfile(models.Model):
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    )

    DEPARTMENT_CHOICES = (
        ('commerce', 'Commerce'),
        ('computer_applications', 'Computer Applications'),
        ('social_work', 'Social Work'),
        ('communication_media', 'Communication and Media Studies'),
        ('applied_economics', 'Applied Economics'),
        ('business_admin', 'Business Administration'),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='teacher_profile')
    subject = models.CharField(max_length=100, blank=True, null=True)
    qualification = models.CharField(max_length=100, blank=True, null=True)
    experience = models.IntegerField(default=0)
    contact_number = models.CharField(max_length=15, blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    profile_picture = models.ImageField(upload_to='teacher_profiles/', blank=True, null=True)
    department = models.CharField(max_length=50, choices=DEPARTMENT_CHOICES, blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} - {self.department} - {self.status}"

# Updated Student Profile Model
class StudentProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='student_profile')
    teacher = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='students')
    roll_number = models.CharField(max_length=50, unique=True)  # Added Roll Number
    date_of_birth = models.DateField(blank=True, null=True)  # Added Date of Birth
    grade = models.CharField(max_length=10, blank=True, null=True)  # Added Grade
    parent_contact = models.CharField(max_length=15, blank=True, null=True)  # Added Parent Contact Number

    def __str__(self):
        return f"Student: {self.user.username}, Roll No: {self.roll_number}, Assigned to: {self.teacher.username if self.teacher else 'No Teacher'}"