from rest_framework import serializers
from .models import *
from django.utils.encoding import smart_str,force_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

class MyUserserializrs(serializers.ModelSerializer):
    password2=serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model=MyUser
        fields=["email","name","password","password2"]

        extra_kwargs={
            'password':{'write_only':True}
        }

    def validate(self, attrs):
        password=attrs.get("password")
        password2=attrs.get("password2")
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password Doesn't Match")
        return attrs
    
    def create(self, validated_data):
        return MyUser.objects.create_user(**validated_data)
    
class MyUserLoginserializrs(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model=MyUser
        fields=["email","password"]

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=MyUser
        fields=['id','email','name']

class ProfileallSerializer(serializers.ModelSerializer):
    user=ProfileSerializer()
    class Meta:
        model=profile
        fields=['user','college_name', 'class_name', 'address', 'phone_number']


class ChangePasswordSerializers(serializers.Serializer):
    password=serializers.CharField(max_length=255, style={'input_type':'password'},write_only=True)
    password2=serializers.CharField(max_length=255,style={'input_type':'password'},write_only=True)
    class Meta:
        fields=["password","password2"]

    def validate(self, attrs):
        password=attrs.get('password')
        password2=attrs.get('password2')
        user=self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password Doesn't Match")
        user.set_password(password)
        user.save()
        return attrs
    
class allbookShow(serializers.ModelSerializer):
    class Meta:
        model=Book
        fields=['id','title','author','unique_code','is_available','img']

class BookSerializer(serializers.ModelSerializer):
    class Meta:
        model=Book
        fields=["title","author"]

    def create(self, validated_data):
        return Book.objects.create(**validated_data)

class BorrowRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = BorrowRequest
        fields = ['book', 'start_date', 'end_date']
    
    def validate(self, data):
        user = self.context['request'].user
        print(user)
        if user.is_librarian:
            print(user.is_library_user)
            raise serializers.ValidationError("Librarians cannot create borrow requests.")
        book = data['book']
        if not book.is_available:
            raise serializers.ValidationError("This book is not available for borrowing.")
        
        # Check for overlapping borrow requests
        if BorrowRequest.objects.filter(
            book=book, 
            status='approved', 
            start_date__lte=data['end_date'],
            end_date__gte=data['start_date']
        ).exists():
            raise serializers.ValidationError("The book is already borrowed during the requested dates.")
        
        return data
    

class BorrowRequestStatusUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = BorrowRequest
        fields = ['status']
    def validate_status(self, value):
        if value not in [BorrowRequest.APPROVED, BorrowRequest.DENIED ,BorrowRequest.RETURNED]:
            raise serializers.ValidationError("Status must be 'Approved' or 'Denied'.")
        return value

    def update(self, instance, validated_data):
        status = validated_data.get('status', instance.status)

        if status == BorrowRequest.APPROVED:
            book = instance.book
            if not book.is_available:
                raise serializers.ValidationError("This book is already borrowed and unavailable.")
            book.is_available = False
            book.save()
        elif status == BorrowRequest.RETURNED:
            book = instance.book
            book.is_available = True
            book.save() 
        elif status == BorrowRequest.DENIED:
            pass
        instance.status = status
        instance.save()

        return instance

class BorrowHistorySerializer(serializers.ModelSerializer):
    book_title = serializers.CharField(source='book.title', read_only=True)
    book_author = serializers.CharField(source='book.author', read_only=True)
    email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = BorrowRequest
        fields = ['id', 'email','book_title', 'book_author', 'start_date', 'end_date', 'status']
    