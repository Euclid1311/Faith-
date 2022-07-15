from cgi import print_exception
from distutils.command.upload import upload
from email.policy import default
from category.models import MainCategory,Category,Sub_Category
from operator import mod

from django.db import models
from django.urls import reverse

# Create your models here.

#PRODUCT

class Product(models.Model):
    product_name = models.CharField(max_length=200,unique=True)
    slug         = models.SlugField(max_length=200, unique=True)
    description  = models.TextField(max_length=500,blank=True)
    price        = models.IntegerField()
    images       = models.ImageField(upload_to='photos/products')
    stock        = models.IntegerField()
    is_available = models.BooleanField(default=True)
    brand        = models.CharField(max_length=100,null=True, blank=True)
    main_category= models.ForeignKey(MainCategory,on_delete=models.CASCADE,null=True, blank=True)
    category     = models.ForeignKey(Category, on_delete=models.CASCADE,null=True, blank=True)
    sub_category = models.ForeignKey(Sub_Category,on_delete=models.CASCADE,null=True, blank=True)
    created_date = models.DateTimeField(auto_now_add=True)
    modified_date= models.DateTimeField(auto_now_add=True)

    def get_url(self):
        return reverse('product_detail', args=[self.main_category.slug,self.category.slug,self.sub_category.slug,self.slug])

    def __str__(self):
        return self.product_name

#VARIATIONMANAGER
class VariationManager(models.Manager):
    def colors(self):
        return super(VariationManager, self).filter(variation_category='color', is_active=True)
    
    def sizes(self):
        return super(VariationManager, self).filter(variation_category='size', is_active=True)


#VARIATIONS
variation_category_choice = (
    ('color', 'color'),
    ('size', 'size'),
)
class Variation(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    variation_category = models.CharField(max_length=100, choices=variation_category_choice)
    variation_value=models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    created_date=models.DateTimeField(auto_now=True)

    objects = VariationManager()
   
    def __str__(self):
        return self.variation_value