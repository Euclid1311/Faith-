from .models import Category,MainCategory,Sub_Category


def menu_links(request):
    links = MainCategory.objects.all()
    return dict(links=links)

   