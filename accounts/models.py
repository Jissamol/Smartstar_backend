from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator

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
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('teacher', 'Teacher'),
        ('student', 'Student'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='student')
    is_active = models.BooleanField(default=True)

    objects = UserManager()

    def __str__(self):
        return self.email

# Teacher Profile (Linked to User)
class TeacherProfile(models.Model):
    DEPARTMENT_CHOICES = (
        ('computer_science', 'Computer Science'),
        ('electronics', 'Electronics'),
        ('mechanical', 'Mechanical'),
        ('civil', 'Civil'),
        ('electrical', 'Electrical'),
        ('communication_media', 'Communication Media'),
    )

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='teacher_profile')
    subject = models.CharField(max_length=100)
    qualification = models.CharField(max_length=100)
    experience = models.IntegerField()
    contact_number = models.CharField(max_length=15)
    department = models.CharField(max_length=50, choices=DEPARTMENT_CHOICES)
    profile_picture = models.ImageField(upload_to='profile_pictures/', null=True, blank=True)
    status = models.CharField(max_length=20, choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected')], default='pending')

    def __str__(self):
        return f"{self.user.username}'s Profile"

# Student Profile Model
class StudentProfile(models.Model):
    DEPARTMENT_CHOICES = (
        ('computer_science', 'Computer Science'),
        ('electronics', 'Electronics'),
        ('mechanical', 'Mechanical'),
        ('civil', 'Civil'),
        ('electrical', 'Electrical'),
        ('communication_media', 'Communication Media'),
    )
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='student_profile')
    department = models.CharField(max_length=50, choices=DEPARTMENT_CHOICES)
    roll_number = models.CharField(max_length=20, unique=True)
    semester = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(8)])

    def __str__(self):
        return f"{self.user.username}'s Profile"