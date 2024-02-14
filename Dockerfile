FROM python:3.8

WORKDIR /code

COPY ./ /code

RUN pip install --upgrade -r /code/requirements.txt

# 
# COPY ./main.py /code/

# 
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]