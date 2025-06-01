# API code
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import *
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from .models import *
import csv
from django.http import HttpResponse

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegisterApiView(APIView):
    def post(self,request,format=None):
        serializer=MyUserserializrs(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user=serializer.save()
            return Response({"msg":"registetion successfull"},status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
from django.db.models import Count

class LoginApiView(APIView):
    def post(self,request,format=None):
        serializer=MyUserLoginserializrs(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email=serializer.data.get("email")
            password=serializer.data.get("password")
            user=authenticate(email=email,password=password)
            if user is not None:
                if user.is_librarian:
                    books = Book.objects.all()
                    print(books)
                else:
                    books = Book.objects.filter(is_available=True)
                serialized_books = allbookShow(books, many=True)
                token=get_tokens_for_user(user)
                return Response({"Token":token,"book_list":serialized_books.data},status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'None field Errors',['Email and password Not found']}},status=status.HTTP_404_NOT_FOUND)

from rest_framework_simplejwt.authentication import JWTAuthentication


class BooksAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        jwt_auth = JWTAuthentication()
        user, _ = jwt_auth.authenticate(request)

        if user.is_librarian:
            books = Book.objects.all()
        else:
            books = Book.objects.filter(is_available=True)
        serializer=allbookShow(books, many = True)
        return Response(serializer.data, status=status.HTTP_200_OK)
       
class BookCreateAPIView(APIView):
    permission_classes=[IsAuthenticated]
    def post(self, request):
        if not request.user.is_librarian:
            return Response({"error": "You are not authorized to add books."} ,status=status.HTTP_403_FORBIDDEN)
        serializer=BookSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ProfileApiView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        jwt_auth = JWTAuthentication()
        user_auth_tuple = jwt_auth.authenticate(request)
        user=user_auth_tuple[0]
        profiles=MyUser.objects.get(email=user)
        serializer = ProfileSerializer(profiles)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PasschangeApi(APIView):
    permission_classes=[IsAuthenticated]
    def post(self, request,format=None):
        serializer=ChangePasswordSerializers(data=request.data,context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({"msg":"Password change successfull"},status=status.HTTP_200_OK)
        return Response({'errors':{'None field Errors',['password Not found']}},status=status.HTTP_404_NOT_FOUND)

class BorrowRequestCreateAPIView(APIView):
    permission_classes=[IsAuthenticated]
    def post(self, request):
        user = request.user
        if user.is_librarian:
            return Response({"error": "Librarians cannot create borrow requests."}, status=status.HTTP_403_FORBIDDEN)

        serializer = BorrowRequestSerializer(data=request.data, context={'request': request})
        
        if serializer.is_valid():
            borrow_request = serializer.save(user=user)
            return Response({
                "message": "Borrow request created successfully.",
                "request_id": borrow_request.id
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        

class BorrowRequestApprovalAPIView(APIView):
    permission_classes = [IsAuthenticated]
    def patch(self, request, pk):
        print(pk)
        if not request.user.is_librarian:
            return Response({"error": "You are not authorized to approve or deny borrow requests."},status=status.HTTP_403_FORBIDDEN,)
        try:
            borrow_request = BorrowRequest.objects.get(id=pk)
        except BorrowRequest.DoesNotExist:
            return Response({"error": f"Borrow request with ID {pk} not found."},status=status.HTTP_404_NOT_FOUND,)

        if borrow_request.status not in [BorrowRequest.PENDING, BorrowRequest.APPROVED]:
            return Response({"error": "Only pending or approved requests can be updated."},status=status.HTTP_400_BAD_REQUEST)

        serializer = BorrowRequestStatusUpdateSerializer(borrow_request, data=request.data, partial=True)
        if serializer.is_valid():
            updated_borrow_request = serializer.save()

            if updated_borrow_request.status == BorrowRequest.APPROVED:
                book = borrow_request.book
                if not book.is_available:
                    return Response({"error": f"The book '{book.title}' is already unavailable."},status=status.HTTP_400_BAD_REQUEST,)
                book.is_available = False
                book.save()
            elif updated_borrow_request.status == BorrowRequest.RETURNED:
                book = borrow_request.book
                book.is_available = True
                book.save()
            return Response({"message": "Borrow request updated successfully.", "data": serializer.data},status=status.HTTP_200_OK,)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


from rest_framework.pagination import PageNumberPagination

class BorrowHistoryAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):   
        if request.user.is_librarian:
            borrow_requests = BorrowRequest.objects.all()
        else:
            borrow_requests = BorrowRequest.objects.filter(user=request.user)

        serializer = BorrowHistorySerializer(borrow_requests, many=True)
        return Response(serializer.data ,status=status.HTTP_200_OK )
    

class DownloadBorrowHistoryCSV(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_email=None):
        if not user_email:
            user = request.user
        else:
            user = MyUser.objects.get(email=user_email)
        if request.user.is_librarian:
            borrow_requests = BorrowRequest.objects.filter(user=user)
        else:
            borrow_requests = BorrowRequest.objects.filter(user=request.user)
        if not borrow_requests.exists():
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="borrow_history_{user.email}.csv"'
            writer = csv.writer(response)
            writer.writerow(['User Name', 'Book Title', 'Book Author', 'Start Date', 'End Date', 'Status'])
            writer.writerow(['No Data', '-', '-', '-', '-', '-'])
            return response

        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="borrow_history_{user.email}.csv"'
        writer = csv.writer(response)
        writer.writerow(['User Name', 'Book Title', 'Book Author', 'Start Date', 'End Date', 'Status'])

        for borrow_request in borrow_requests:
            writer.writerow([
                borrow_request.user.name,
                borrow_request.book.title,
                borrow_request.book.author,
                borrow_request.start_date,
                borrow_request.end_date,
                borrow_request.status
            ])

        return response

    
# Acctual program of Project
import requests
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
import json
from django.contrib import messages
from .forms import *
from collections import Counter
API_BASE_URL = "http://127.0.0.1:8000/api"

def user_login(request):
    if request.method == 'POST':
        email = request.POST.get('username')
        password = request.POST.get('password')
        user=MyUser.objects.get(email=email)
        response = requests.post(f"{API_BASE_URL}/login/", data={'email': email, 'password': password})
        if response.status_code == 200:
            data = response.json()
            request.session['access_token'] = data['Token']['access']
            request.session['refresh_token'] = data['Token']['refresh']
            
            if user.is_librarian:
                return redirect('librarian_dashboard')
            else:
                return redirect('user_dashboard')
        else:
            messages.error(request, "Invalid email or password.")

    return render(request, 'login.html')


from collections import defaultdict

def user_dashboard(request):
    access_token = request.session.get('access_token')

    if not access_token:
        return redirect('login')

    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f"{API_BASE_URL}/books/", headers=headers)
    jwt_auth = JWTAuthentication()
    validated_token = jwt_auth.get_validated_token(access_token)
    user = jwt_auth.get_user(validated_token)

    if response.status_code == 200:
        books = response.json()

        # Group books by title and author
        book_data = defaultdict(lambda: {"copies": [], "img": None})
        for book in books:
            key = (book['title'], book['author'])
            book_data[key]["copies"].append({
                'id': book['id'],
                'status': "Available" if book['is_available'] else "Checked Out"
            })
            # Use the first image for the book
            if not book_data[key]["img"]:
                book_data[key]["img"] = book['img']

        # Prepare the book list with aggregated data
        book_list_with_copies = [
            {
                'title': title,
                'author': author,
                'img': data["img"],
                'count': len(data["copies"]),
                'copies': data["copies"]
            }
            for (title, author), data in book_data.items()
        ]

        return render(request, 'user_dashboard.html', {'books': book_list_with_copies, 'user': user})

    elif response.status_code == 401:
        messages.error(request, "Unauthorized access. Please log in.")
        return redirect('login')
    elif response.status_code == 403:
        messages.error(request, "Forbidden access.")
        return redirect('login')
    elif response.status_code == 500:
        messages.error(request, "An error occurred while fetching books.")
        return redirect('login')
    else:
        messages.error(request, "Unable to fetch books. Please try again.")
        return redirect('login')




def librarian_dashboard(request):
    access_token = request.session.get('access_token')
   
    if not access_token:
        return redirect('login') 
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f"{API_BASE_URL}/books/", headers=headers)
    jwt_auth = JWTAuthentication()
    validated_token = jwt_auth.get_validated_token(access_token)
    user = jwt_auth.get_user(validated_token)
    
    if response.status_code == 200:
        books = response.json()

        book_counts = Counter((book['title'], book['author']) for book in books)

        present_counts = Counter((book['title'], book['author']) for book in books if book['is_available'])

        book_list_with_counts = []
        for (title, author), count in book_counts.items():
            present = present_counts.get((title, author), 0) 
            book_list_with_counts.append({
                'title': title,
                'author': author,
                'count': count,
                'present': present
            })

        return render(request, 'books.html', {
            'books': book_list_with_counts,
            'user': user
        })

    elif response.status_code == 401:
        messages.error(request, "Unauthorized access. Please log in.")
        return redirect('login')
    elif response.status_code == 403:
        messages.error(request, "Forbidden access.")
        return redirect('login')
    elif response.status_code == 500:
        messages.error(request, "An error occurred while fetching books.")
        return redirect('login')
    else:
        messages.error(request, "Unable to fetch books. Please try again.")
        return redirect('login')


def avilabelBooks(request):
    access_token = request.session.get('access_token')
    if not access_token:
        return redirect('login')
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f"{API_BASE_URL}/books/", headers=headers) 
    if response.status_code == 200:
        books = response.json()
        available_books = [book for book in books if book['is_available']]
        unavailable_books = [book for book in books if not book['is_available']]
        return render(request, 'avilabelBooks.html', {
            'books': available_books,
            'unavailable_books': unavailable_books,
        })



def create_borrow_request(request, book_id):
    access_token = request.session.get('access_token')
    if not access_token:
         return redirect('login')
    body_data = json.loads(request.body)
    start_date = body_data.get('start_date')
    end_date = body_data.get('end_date')
    if not start_date or not end_date:
        return JsonResponse({"error": "Start date and end date are required."}, status=400)
    headers = {'Authorization': f'Bearer {access_token}'}
    payload = {
            "book": book_id,
            "start_date": start_date,
            "end_date": end_date,
        }
    response = requests.post(f"{API_BASE_URL}/requestbook/", headers=headers, json=payload)
    print(response)
    if response.status_code == 201:
        return JsonResponse({"message": "Borrow request created successfully!"}, status=201)
    return JsonResponse({"error": "Invalid request method."}, status=400)

def register_user(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        name = request.POST.get('name')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        payload = {
            "email": email,
            "name": name,
            "password": password,
            "password2": password2,
            }
        response = requests.post(f"{API_BASE_URL}/registre/",json=payload)
        if response.status_code == 201:
            messages.success(request, "Account created successfully! You can now log in.")
            return redirect('login')
    return render(request,"register.html")

def edit_profile(request, id=None):
    access_token = request.session.get('access_token')
    if not access_token:
        return redirect('login')
    if id is None:
        jwt_auth = JWTAuthentication()
        validated_token = jwt_auth.get_validated_token(access_token)
        user = jwt_auth.get_user(validated_token)
        id = user.id
    usp = get_object_or_404(MyUser, id=id)
    user_profile = profile.objects.filter(user=usp).first()

    if request.method == "POST":
        user_form = UserForm(request.POST, instance=usp)
        profile_form = ModelForm(request.POST, instance=user_profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            if not user_profile:
                user_profile = profile(user=usp)
            profile_form = ModelForm(request.POST, instance=user_profile)
            profile_form.save()

            messages.success(request, "Your profile has been updated!")
            return redirect('profile')
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        user_form = UserForm(instance=usp)
        profile_form = ModelForm(instance=user_profile)

    context = {
        'user_form': user_form,
        'profile_form': profile_form,
    }
    return render(request, 'edit_profile.html', context)


def listofbook(request, name):
    access_token = request.session.get('access_token')
    if not access_token:
        return redirect('login') 

    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = requests.get(f"{API_BASE_URL}/books/", headers=headers)
        
        if response.status_code == 200:
            books = response.json()
            
            matched_books = [book for book in books if book.get('title').lower() == name.lower()]

            if matched_books:
                return render(request, 'booklist.html', {'books': matched_books})
            else:
                return render(request, 'booklist.html', {'error': "No books found matching the title."})
        
        else:
            return render(request, 'booklist.html', {'error': "Failed to retrieve books. Please try again later."})
    
    except requests.exceptions.RequestException as e:
        return render(request, 'booklist.html', {'error': f"An error occurred: {str(e)}"})



def AddBook(request):
    access_token = request.session.get('access_token')
    if not access_token:
        return redirect('login')
    if request.method == "POST":
        form = AddBookForm(request.POST)
        if form.is_valid():
            headers = {'Authorization': f'Bearer {access_token}'}
            data = form.cleaned_data 
            response = requests.post(f"{API_BASE_URL}/AddBook/", headers=headers, json=data)
            if response.status_code == 201:
                messages.success(request, "Book added successfully!")
                return redirect('librarian_dashboard')
            else:
                messages.error(request, f"Failed to add book: {response.text}")

    else:
        form = AddBookForm()

    return render(request, 'add_book.html', {'form': form})


def borrow_history_user(request):
    access_token = request.session.get('access_token')
    
    if not access_token:
        return redirect('login')
    
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f"{API_BASE_URL}/History/", headers=headers)
    
    jwt_auth = JWTAuthentication()
    validated_token = jwt_auth.get_validated_token(access_token)
    user = jwt_auth.get_user(validated_token)
    
    if response.status_code == 200:
        history = response.json()
        pending_history = [h for h in history if h.get('status') == 'Pending']
        return render(request, 'borrow_history.html', {"pending_history": pending_history,"user": user})
    
    return render(request, 'borrow_history.html', {"user": user})

def IssuedBook(request):
    access_token = request.session.get('access_token')
    
    if not access_token:
        return redirect('login')
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f"{API_BASE_URL}/History/", headers=headers)
    
    jwt_auth = JWTAuthentication()
    validated_token = jwt_auth.get_validated_token(access_token)
    user = jwt_auth.get_user(validated_token)
    
    if response.status_code == 200:
        history = response.json()
        approved_history = [h for h in history if h.get('status') == 'Approved'] 
        return render(request, 'IssuedBook.html',{"approved_history":approved_history,"user": user})

def profile_view(request):
    access_token = request.session.get('access_token')
    
    if not access_token:
        return redirect('login')
    
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f"{API_BASE_URL}/profile/", headers=headers)
    print(response)
    if response.status_code==200:
        profiles=response.json()
        pro=profiles.get("email")
        try:
            val=profile.objects.get(user__email=pro)
        except:
            val=None
        if val == None:
            return redirect('update')
        return render(request, 'profile.html',{"user":profiles,"pro":val})
    elif response.status_code == 401:
        messages.error(request, "Unauthorized access. Please log in.")
        return redirect('login')
    elif response.status_code == 403:
        messages.error(request, "Forbidden access.")
        return redirect('login')    
    elif response.status_code == 404:
        return redirect('update')
    else:
        messages.error(request, "Unable to fetch profile. Please try again.")
        return redirect('login')

def download_borrow_history(request, user_email=None):
    access_token = request.session.get('access_token')
    if not access_token:
        return redirect('login')

    headers = {'Authorization': f'Bearer {access_token}'}
    if user_email == None:
        response = requests.get(f"{API_BASE_URL}/download/", headers=headers)
    else:
        response = requests.get(f"{API_BASE_URL}/download/{user_email}", headers=headers)
    
    if response.status_code == 200:
        response_content = HttpResponse(
            response.content,
            content_type='text/csv'
        )
        # Dynamic filename using user email or generic if not provided
        filename = f"borrow_history_{user_email}.csv" if user_email else "borrow_history.csv"
        response_content['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response_content

    return render(request, "borrow_history.html", {'error': "Unable to download borrow history."})




def request_approval(request, pk):
    if request.method == 'POST':
        action = request.POST.get('action')
        print(action)
    access_token = request.session.get('access_token')
    if not access_token:
        return redirect('login')
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.patch(f"{API_BASE_URL}/approval/{pk}", headers=headers , data={'status':action})
    print(response)
    if response.status_code == 200:
        messages.success(request, "Borrow request updated scuccessfully !")
        return redirect('IssuedBook')
    return render(request, 'borrow_history.html')


def search_books(request):
    query = request.GET.get('q', '')  # Get the search query from the GET request
    if query:
        # Search for books by title or author (or other fields as needed)
        books = Book.objects.filter(title__icontains=query) | Book.objects.filter(author__icontains=query)
    else:
        books = Book.objects.all()  # If no search query, show all books
    
    return render(request, 'librarian_dashboard.html', {'books': books, 'query': query})

def custom_logout(request):
    request.session.flush()
    return redirect('login')    