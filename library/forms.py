from django import forms
from .models import *
from django.forms import TextInput,NumberInput,EmailInput

class UserForm(forms.ModelForm):
    class Meta:
        model = MyUser
        fields = ['name', 'email']

        widgets = {
            'name':TextInput(attrs={'class': 'form-control'}),
            'email': EmailInput(attrs={'class': 'form-control'}),

        }

class ModelForm(forms.ModelForm):
    class Meta:
        model=profile
        fields= 'college_name', 'class_name', 'address', 'phone_number'
        

        widgets = {
            'college_name':TextInput(attrs={'class': 'form-control'}),
            'class_name': TextInput(attrs={'class': 'form-control'}),
            'address': TextInput(attrs={'class': 'form-control'}),
            'phone_number': NumberInput(attrs={'class': 'form-control'}),
        }

class AddBookForm(forms.ModelForm):
    class Meta:
        model=Book
        fields=['title','author']

        widgets={
            'title':TextInput(attrs={'class':'form-control'}),
            'author':TextInput(attrs={'class':'form-control'})
        }