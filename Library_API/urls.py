from django.contrib import admin
from django.urls import path,include
from django.conf.urls.static import static
from django.conf import settings
from rest_framework_simplejwt.views import TokenObtainPairView,TokenRefreshView
from library.views import *
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('library.urls')),
    # path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    # path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('', user_login, name='login'),
    path('logout/', custom_logout, name='logout'),
    path('register/', register_user, name='register'),
    path('IssuedBook/', IssuedBook, name='IssuedBook'),
    path('listofbook/<str:name>/', listofbook, name='listofbook'),
    path('update/<int:id>', edit_profile, name='update'),
    path('update/', edit_profile, name='update'),
    path('profile/', profile_view, name='profile'),
    path('AddBook/', AddBook, name='AddBook'),
    path('search_books/', search_books, name='search_books'),
    path('avilabelBooks/', avilabelBooks , name='avilabelBooks'),
    path('update_status/<int:pk>', request_approval, name='update_status'),
    path('custom_logout/', custom_logout, name='custom_logout'),
    path('user-dashboard/', user_dashboard, name='user_dashboard'),
    path('user-history/', borrow_history_user, name='user_history'),
    path('download/<str:user_email>/', download_borrow_history, name='download'),
    path('download/', download_borrow_history, name='download'),
    path('librarian-dashboard/', librarian_dashboard, name='librarian_dashboard'),
    path('borrow-request/<int:book_id>/', create_borrow_request, name='borrow-request'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
