from django.urls import path
from . import views

urlpatterns = [
    path('',views.store,name='store'),
    path('main_category/<slug:main_category_slug>/',views.store,name='product_by_main_category'),
    path('main_category/category/<slug:main_category_slug>/<slug:category_slug>/',views.store,name='product_by_category'),
    path('main_category/category/sub_category/<slug:main_category_slug>/<slug:category_slug>/<slug:sub_category_slug>/',views.store,name='product_by_sub_category'),
    path('main_category/category/sub_category/<slug:main_category_slug>/<slug:category_slug>/<slug:sub_category_slug>/<slug:product_slug>/',views.product_detail,name='product_detail'),
    path('search/',views.search, name='search'),

]  