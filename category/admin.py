from django.contrib import admin
from .models import Category, MainCategory, Sub_Category
# Register your models here.


class CategoryAdmin(admin.ModelAdmin):
    prepopulated_fields={'slug':('category_name',)}
    list_display= ('category_name','slug')
admin.site.register(MainCategory,CategoryAdmin)

class CategoryAdmin(admin.ModelAdmin):
    prepopulated_fields={'slug':('category_name',)}
    list_display= ('category_name','slug','main_category')
admin.site.register(Category,CategoryAdmin)


class CategoryAdmin(admin.ModelAdmin):
    prepopulated_fields={'slug':('category_name',)}
    list_display= ('category_name','slug','category')
admin.site.register(Sub_Category,CategoryAdmin)

