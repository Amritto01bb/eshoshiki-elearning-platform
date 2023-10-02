from django.urls import path, re_path
from . import views


urlpatterns = [
    path("set-language/<str:language>", views.set_language, name="set-language"),
    path('', views.index_page, name='index'),
    #path('features', views.featuresPage, name='features'),
    #path('about', views.aboutPage, name='about'),
    #path('pricing', views.pricingPage, name='pricing'),
    #path('contacts', views.contactsPage, name='contacts'),
    #path('testimonials', views.testimonialsPage, name='testimonials'),
    #path('faq', views.faqPage, name='faq'),
    #path('forgotten-password', views.forgottenPasswordPage, name='forgotten-password'),

    #path('profile', views.profilePage, name='profile'),
    #path('dashboard', views.dashboardPage, name='dashboard'),
    #path('dashboard/data-management', views.dataManagementPage, name='data-management'),

    #path('category', views.category_page, name='category'),
    #path('subcategory/<int:category_id>', views.subcategory_page, name='subcategory'),
    #path('information/<int:category_id>/<int:subcategory_id>', views.information_page, name='information'),
    #path('category/<str:parent>/<str:index>', views.informationPage, name='information'),


    #path('questions', views.questions_page, name='questions'),
    #path('questions/<int:question_id>', views.view_question_page, name='questions'),
    #path('questions/<int:question_id>/<int:answer_id>', views.view_question_page, name='questions'),
    #path('questions/ask', views.ask_question_page, name='ask-question'),
    #path('questions/<int:question_id>/edit', views.update_question_page, name='update-question'),
    #path('questions/<int:question_id>/delete', views.delete_question_page, name='delete-question'),
    #path('questions/<int:question_id>/<int:answer_id>/edit', views.update_answer_page, name='update-answer'),
    #path('questions/<int:question_id>/<int:answer_id>/delete', views.delete_answer_page, name='delete-answer'),

    #path('chat/expert', views.chat_expert_page, name='chat-expert'),
    #path('chat/expert/<int:problem_id>', views.chat_expert_page, name='chat-expert'),

    #path('chat/user', views.chat_user_page, name='chat-user'),
    #path('chat/user/<int:problem_id>', views.chat_user_page, name='chat-user'),
    #path('chat/request-expert', views.request_expert_page, name='request-expert'),

    #path('chat/ai', views.chat_ai_page, name='chat-ai'),
    #path('chat/ai/<int:problem_id>', views.chat_ai_page, name='chat-ai'),
    #path('chat/request-ai', views.request_ai_page, name='request-ai'),

    #path('weather', views.weather_page, name='weather'),
]
