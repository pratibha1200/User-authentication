===============================
userauth
===============================


userauth website

* Free software: BSD license

Requirements
------------

* Django 3.1+
* Python 3.8


Installation
----------------------------

#. Clone the git repository.
#. Create a production.py file in userauth/userauth/userauth/settings by copying what's in the production_example.py
    * Fill database details in the file you just created
    * Add the site admins in the ADMINS variable
    * Add server host in ALLOWED_HOSTS

#. Install all third party packages by running::

    $ pip install -r requirements/development.txt

#. Apply migrations::

    $ python manage.py migrate

