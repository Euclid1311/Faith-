

from django.shortcuts import redirect, render
from django.contrib import messages,auth 

from .forms import RegistrationForm 
from .models import Account
from django.contrib.auth.decorators import login_required

#verificationmail

from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator 
from django.core.mail import EmailMessage

from cart.views import _cart_id
from cart.models import Cart,Cartitem

#redirection
import requests


# Create your views here.
def register(request):
        if request.method == 'POST':
            form = RegistrationForm(request.POST)
            if form.is_valid():
                first_name = form.cleaned_data['first_name']
                last_name  = form.cleaned_data['last_name']
                phone_number = form.cleaned_data['phone_number']
                email = form.cleaned_data['email']
                password = form.cleaned_data['password']
                username = email.split("@")[0]
                user = Account.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
                user.phone_number = phone_number
                user.save()

                # USERACTIVATION
                current_site = get_current_site(request)
                mail_subject = 'Please activate your account'
                message = render_to_string('accounts/account_verification_email.html',{
                    'user': user,
                    'domain': current_site,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': default_token_generator.make_token(user),
                })
                to_email = email
                send_email = EmailMessage(mail_subject,message,to=[to_email])
                send_email.send()

                messages.success(request, 'Registration successful')
                return redirect('/accounts/login/?command=verification&email='+email)
        else:
                form = RegistrationForm()
        context = {
                    'form':form,
                }
        return render(request, 'accounts/register.html',context)

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
   
        user = auth.authenticate(email=email, password=password)
        print(user)
       

        if user is not None:
            try:
                cart = Cart.objects.get(cart_id = _cart_id(request))                                     #try  block checking if any
                is_cart_item_exists =Cartitem.objects.filter( cart=cart).exists()                   #cart items are present before login
                if is_cart_item_exists:
                    cart_item = Cartitem.objects.filter(cart=cart)
                    
                    #getting the product variation by cart id
                    product_variation = []
                    for item in cart_item:
                        variation = item.variations.all()
                        product_variation.append(list(variation))
                        # item.user = user
                        # item.save()

                    #get the cart item from the userside
                    cart_item=Cartitem.objects.filter(user=user)
                    #EXISTING VARIATIONS->FROM DATABASE
                    #CURRENT VARIATIONS->FROM DATABASE
                    # ITEM_ID-> DATABASE#
                    ex_var_list = []
                    id          = []
                    for item in cart_item:
                        existing_variation = item.variations.all()
                        ex_var_list.append(list(existing_variation))
                        id.append(item.id)
                    
                    for pv in product_variation:
                        if pv in ex_var_list:
                            index = ex_var_list.index(pv)
                            item_id = id[index]
                            item = Cartitem.objects.get(id=item_id)
                            item.quantity += 1
                            item.user =user
                            item.save()
                        else:
                            cart_item=Cartitem.objects.filter(cart=cart)
                            for item in cart_item:
                                item.user=user
                                item.save()
            except:
                pass

            auth.login(request,user)
            url = request.META.get('HTTP_REFERER')
            try:
                query = requests.utils.urlparse(url).query
                
                params = dict(x.split('=') for x in query.split('&'))
                if 'next' in params:
                    nextPage = params['next']
                    return redirect(nextPage)
            except:
                return redirect('home')  #redirection
        else:
            messages.error(request, 'invalid details')
            return redirect('login')

    return render(request, 'accounts/login.html')

@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    messages.success(request,'You are logged out.')
    return redirect('login')    

def activate(request,uidb64,token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError,ValueError,OverflowError,Account.DoesNotExist):
        user = None
    
    if user is not None and default_token_generator.check_token(user,token):
        user.is_active = True
        user.save()
        print(user)
        messages.success(request,"Congragulations! Your account is activated.")
        return redirect('login')
    else:
        messages.error(request,"Invalid activation link")
        return redirect('register')


def forgotPassword(request):
    if request.method == 'POST':
        email =request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact =email)

            #forgotpassword email
            current_site = get_current_site(request)
            mail_subject = 'Reset Your Password'
            message = render_to_string('accounts/reset_password_email.html',{
                        'user': user,
                        'domain': current_site,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': default_token_generator.make_token(user),
                            })  
            to_email = email
            send_email = EmailMessage(mail_subject,message,to=[to_email])
            send_email.send()  

            messages.success(request, 'Password reset email has been sent to your email adress')
            return redirect('login')
        else:
            messages.error(request,'Account does not exist') 
            return redirect('forgotPassword')     
                                                                                                                       
        
    return render(request,'accounts/forgotPassword.html')

def resetpassword_validate(request,uidb64,token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError,ValueError,OverflowError,Account.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user,token):
        request.session['uid'] = uid
        messages.success(request, 'Please reset your password')
        return redirect('resetPassword')

    else:
        messages.error(request,'This request has been expired')    
        return redirect('login')

    
def resetPassword(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if confirm_password == password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request,'Password has been changed succesfully')
            return redirect('login')
        
        else:
            messages.error(request,'Password does not match')
            return redirect('resetPassword')
    
    else:
        return render( request,'accounts/resetPassword.html')
        
def dashboard(request):
    return render(request, 'accounts/dashboard.html')



    