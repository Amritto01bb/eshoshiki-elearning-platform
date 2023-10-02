from django.urls import path, re_path
from . import views


urlpatterns = [
    #path("accounts", views.accounts_page, name="accounts"),
    #path("accounts/<int:account_id>", views.accounts_page, name="accounts"),

    #path("view-category", views.viewCategoryPage, name="view-category"),
    #path("insert-category-form", views.insertCategoryPage, name="insert-category-form"),
    #path("update-category-form/<int:category_id>", views.updateCategoryPage, name="update-category-form"),

    #path("view-subcategory", views.viewSubcategoryPage, name="view-subcategory"),
    #path("view-subcategory/<int:category_id>", views.viewSubcategoryPage, name="view-subcategory"),
    #path("insert-subcategory-form", views.insertSubcategoryPage, name="insert-subcategory-form"),
    #path("update-subcategory-form/<int:subcategory_id>", views.updateSubcategoryPage, name="update-subcategory-form"),

    #path("view-disease-problem", views.view_disease_problem_page, name="view-disease-problem"),
    #path("view-disease-problem/<int:subcategory_id>", views.view_disease_problem_page, name="view-disease-problem"),
    #path("insert-disease-problem-form", views.insert_disease_problem_page, name="insert-disease-problem-form"),
    #path("update-disease-problem-form/<int:disease_problem_id>", views.update_disease_problem_page, name="update-disease-problem-form"),

    #path("delete-form/<int:object_id>", views.delete_form, name="delete-form"),
    #path("delete-form/<int:object_id>/<int:data_id>", views.delete_form, name="delete-form"),

    #path('conversation/room/<int:room_id>', views.view_conversation, name='view-conversation'),

    #path('requests/expert', views.expert_requests_page, name='expert-requests'),
    #path('requests/room/<int:room_id>/delete', views.delete_room, name='delete-room'),
    #path('requests/problem/<int:problem_id>/delete', views.delete_problem, name='delete-problem'),
]
