from django.shortcuts import render

# Create your views here.
from django.views.generic import CreateView, DetailView, ListView, TemplateView


class IndexView(TemplateView):
    template_name = 'index.html'
