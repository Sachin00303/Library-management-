from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser


class MyUserManager(BaseUserManager):
    def create_user(self, email, name, password=None ,password2=None):
        """
        Creates and saves a User with the given email, date of
        birth and password.
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(email=self.normalize_email(email),name=name)

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None):
        """
        Creates and saves a superuser with the given email, date of
        birth and password.
        """
        user = self.create_user(email,password=password,name=name)
        user.is_admin = True
        user.is_librarian=True
        user.save(using=self._db)
        return user


class MyUser(AbstractBaseUser):
    email = models.EmailField(verbose_name="email address",max_length=255,unique=True)
    name=models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    is_librarian=models.BooleanField(default=False)
    created_at=models.DateTimeField(auto_now_add=True)
    updated_at=models.DateTimeField(auto_now=True)

    objects = MyUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name"]

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin,self.is_librarian
  
import uuid

class Book(models.Model):
    title = models.CharField(max_length=255)  # Book name
    author = models.CharField(max_length=255, blank=True, null=True)  # Optional: Author of the book
    unique_code = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)  # Unique identifier
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp for when the book was added
    is_available = models.BooleanField(default=True)
    img=models.ImageField(upload_to='images/',blank=True,null=True)

    def __str__(self):
        return f"{self.title} ({self.unique_code})"
    

class BorrowRequest(models.Model):
    PENDING = 'Pending'
    APPROVED = 'Approved'
    DENIED = 'Denied'
    RETURNED='Returned'

    STATUS_CHOICES = [
        (PENDING, 'Pending'),
        (APPROVED, 'Approved'),
        (DENIED, 'Denied'),
        (RETURNED,'Returned')
    ]

    user = models.ForeignKey(MyUser, on_delete=models.CASCADE, related_name='borrow_requests')
    book = models.ForeignKey(Book, on_delete=models.CASCADE, related_name='borrow_requests')
    start_date = models.DateField()
    end_date = models.DateField()
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default=PENDING)

    class Meta:
        unique_together = ('book', 'start_date', 'end_date')

    def __str__(self):
        return f"{self.user.email} - {self.book.title} ({self.status})"

class profile(models.Model):
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE,related_name="profile")
    college_name = models.CharField(max_length=255, blank=True)
    class_name = models.CharField(max_length=255, blank=True)
    address = models.CharField(max_length=300,blank=True)
    phone_number = models.CharField(max_length=15, blank=True)

    def __str__(self):
        return self.user.email
