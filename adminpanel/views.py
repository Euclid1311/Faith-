

from django.contrib import messages


from django.shortcuts import redirect, render
from accounts.models import Account
from category.models import Category, MainCategory,Sub_Category
from store.models import Product, Variation
# Create your views here.

#store imports
from store.forms import ProductForm
from category.forms import MainCategoryForm,CategoryForm,SubCategoryForm
from django.template.defaultfilters import slugify

#cart imports
from cart.models import Cart,Cartitem

from orders.models import Order,OrderProduct,Payment

def dashboard(request):

    return render(request,'adminpanel/dashboard.html')

def accounts_table(request,id):
    active_users = Account.objects.filter(is_admin=False, is_active=True)
    banned_users = Account.objects.filter(is_admin=False, is_active=False)

    context = {
        'active_users':active_users,
        'banned_users':banned_users,
    }
    if id == 1:
        return render(request,'adminpanel/accounts/active_user_account_table.html',context)
    else:
        return render(request,'adminpanel/accounts/banned_user_account_table.html',context)


#functions in account table(ban&unban)
def ban_user(request,id):
    user = Account.objects.get(id=id)
    user.is_active = False
    user.save()
    return redirect('accounts',id=1)

def unban_user(request,id):
    user = Account.objects.get(id=id)
    user.is_active = True
    user.save()   
    return redirect('accounts',id=2)

def cart_table(request,id):
    carts = Cart.objects.all()
    cart_items = Cartitem.objects.all().filter(is_active=True)
    context = {
        'carts' : carts,
        'cart_items' : cart_items,
    }
    
    if id==1:
        return render(request,'adminpanel/cart_table/cart.html',context)
    else:
        return render(request,'adminpanel/cart_table/cart_items.html',context)

def category_table(request,id):
    main_category = MainCategory.objects.all()
    category      = Category.objects.all()
    sub_category  = Sub_Category.objects.all()

    context = {
        'main_category':main_category,
        'category':category,
        'sub_category':sub_category,
    }
    if id == 1: 
        return render(request, 'adminpanel/category_table/main_category.html',context)
    if id == 2:
        return render(request, 'adminpanel/category_table/category.html',context)
    else:
        return render(request, 'adminpanel/category_table/sub_category.html',context)



#category_table functions(add====dlt=======edit)
def add_main_category(request):
    form = MainCategoryForm()
    if request.method == 'POST':
        form = MainCategoryForm(request.POST)
        if form.is_valid():
            main_category = form.save()
            category_name = form.cleaned_data['category_name']
            slug          = slugify(category_name)
            main_category.slug = slug
            main_category.save()
            messages.success(request,'New Main-category added successfully')
            return redirect('category_table', id=1)
    context = {
        'form':form,
    }
    return render(request, 'adminpanel/category_table/add_main_category.html',context)

def edit_main_category(request,id):
    main_category = MainCategory.objects.get(id=id)
    print(main_category)
    if request.method == 'POST':
        form = MainCategoryForm(request.POST,request.FILES,instance=main_category)
        if form.is_valid():
            category_name = form.cleaned_data['category_name']
            slug          = slugify(category_name)
            main_category = form.save()
            main_category.slug = slug
            main_category.save()
            messages.success(request, 'Main-category edited succesfully')
            return redirect('category_table',id=1)
    else:
        form = MainCategoryForm(instance=main_category)
    context = {
        'form':form,
    }
    return render(request,'adminpanel/category_table/add_main_category.html',context)

def delete_main_category(request,id):
    main_category = MainCategory.objects.get(id=id)
    main_category.delete()
    return redirect('category_table',id=1)

#CATEGORY
def add_category(request):
    form = CategoryForm()
    if request.method == 'POST':
        form = CategoryForm(request.POST)
        if form.is_valid():
            category = form.save()
            category_name = form.cleaned_data['category_name']
            slug = slugify(category_name)
            category.slug = slug
            category.save()
            messages.success(request,'New category added successfully')
            return redirect('category_table',id=2)
    context = {
        'form' : form,
    }
    return render (request,'adminpanel/category_table/add_category.html',context)

def edit_category(request,id):
    category = Category.objects.get(id=id)
    if request.method == 'POST':
        form = CategoryForm(request.POST,request.FILES, instance=category)
        if form.is_valid():
            category_name = form.cleaned_data['category_name']
            slug = slugify(category_name)
            category = form.save()
            category.slug = slug
            category.save()
            messages.success(request,'category editted successfully')
            return redirect('category_table',id=2)
    else:
        form = CategoryForm(instance=category)
    context = {
        'form' : form,
    }
    return render (request,'adminpanel/category_table/add_category.html',context)

def delete_category(request,id):
    category = Category.objects.get(id=id)
    category.delete()
    return redirect ('category_table',id=2)

def add_sub_category(request):
    form = SubCategoryForm()
    if request.method == 'POST':
        form = SubCategoryForm(request.POST)
        if form.is_valid():
            sub_category = form.save()
            category_name = form.cleaned_data['category_name']
            slug = slugify(category_name)
            sub_category.slug = slug
            sub_category.save()
            messages.success(request,'New sub-category added successfully')
            return redirect('category_table',id=3)
    context = {
        'form' : form,
    }
    return render (request,'adminpanel/category_table/add_sub_category.html',context)

def edit_sub_category(request,id):
    sub_category = Sub_Category.objects.get(id=id)
    if request.method == 'POST':
        form = SubCategoryForm(request.POST,request.FILES, instance=sub_category)
        if form.is_valid():
            category_name = form.cleaned_data['category_name']
            slug = slugify(category_name)
            sub_category = form.save()
            sub_category.slug = slug
            sub_category.save()
            messages.success(request,'Sub-category editted successfully')
            return redirect('category_table',id=3)
    else:
        form = SubCategoryForm(instance=sub_category)
    context = {
        'form' : form,
    }
    return render (request,'adminpanel/category_table/add_sub_category.html',context)

def delete_sub_category(request,id):
    sub_category = Sub_Category.objects.get(id=id)
    sub_category.delete()
    return redirect('category_table',id=3)

def order_table(request,id):
    orders = Order.objects.all()
    order_products = OrderProduct.objects.all()
    payments = Payment.objects.all()
    context = {
        'orders' : orders,
        'order_products' : order_products,
        'payments' : payments,
    }

    if id==1:
        return render (request,'adminpanel/order_table/orders.html',context)
    elif id==2:
        return render(request,'adminpanel/order_table/order_products.html',context)
    else:
        return render(request,'adminpanel/order_table/payments.html',context)

#store
def store_table(request,id):
    products = Product.objects.all()
    variations =Variation.objects.all()

    context = {
        'products' : products,
        'variations' : variations,
    }
    if id==1:
        return render(request,'adminpanel/store_table/products.html',context)
    else:
        return render(request,'adminpanel/store_table/variations.html',context)

def add_product(request):
    form = ProductForm()
    if request.method == 'POST':
        form = ProductForm(request.POST,request.FILES)
        print(form)
        if form.is_valid():
            product = form.save(commit=False)
            product_name = form.cleaned_data['product_name']
            slug = slugify(product_name)
            product.slug = slug

            product.save()
            return redirect('store_table',id=1)
    else:
        form = ProductForm()
    context = {
        'form' : form,
    }
    return render(request,'adminpanel/store_table/add_product.html',context)

def edit_product(request,id):
    product = Product.objects.get(id=id)
    if request.method =='POST':
        form = ProductForm(request.POST,request.FILES,instance=product)
        if form.is_valid():
            product_name = form.cleaned_data['product_name']
            slug = slugify(product_name)
            product = form.save()
            product.product_slug = slug
            product.save()
            return redirect('store_table',id=1)
    else:
        form = ProductForm(instance=product)
    context = {
        'form' : form,
    }
    return render (request,'adminpanel/store_table/add_product.html',context)

def delete_product(request, id):
    product = Product.objects.get(id=id)
    product.delete()
    return redirect('store_table',id=1)

# #products
# def store_table(request, id):
#     products = Product.objects.all()
#     variations = Variation.objects.all()

#     context = {
#         'products':products,
#         'variations':variations,
#     }
#     if id == 1:
#         return render(request, 'adminpanel/store_table/products.html',context)
#     else:
#         return render(request, 'adminpanel/store_table/variations.html',context)

# #store operations
# def add_product(request):
#     form = ProductForm()
#     if request.method == 'POST':
#         form = ProductForm(request.POST, request.FILES)
#         print(form)
#         if form.is_valid():
#             product = form.save(commit=False)
#             product_name = form.cleaned_data['product_name']
#             slug = slugify(product_name)
#             product.product_slug = slug

#             product.save()
#             return redirect('store_table',id=1)
#     else:
#         form = ProductForm()
#     context = {
#         'form' : form,
#     }
#     return render(request,'adminpanel/store_table/add_product.html',context)



