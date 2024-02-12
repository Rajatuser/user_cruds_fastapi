import codecs
import os
base_dir = os.path.dirname(os.path.abspath(__file__))
f=codecs.open(base_dir+'/templates/resetPassword.html', 'r')
forgot_html = f.read()

def forgot_template():
    temp = f'{forgot_html}'
    return temp
