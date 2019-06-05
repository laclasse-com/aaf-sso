FROM php:alpine
COPY . /app/
WORKDIR /app
EXPOSE 80
CMD ["php", "-S", "0.0.0.0:80"]
