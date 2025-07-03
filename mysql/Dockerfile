FROM mysql:8.0.30

# Khai báo các biến đầu vào (được truyền khi build image)
ARG MYSQL_DATABASE
ARG MYSQL_USER
ARG MYSQL_PASSWORD
ARG MYSQL_ROOT_PASSWORD
ARG MYSQL_PORT

# Thiết lập các biến môi trường bên trong container
ENV MYSQL_DATABASE=$MYSQL_DATABASE
ENV MYSQL_USER=$MYSQL_USER
ENV MYSQL_PASSWORD=$MYSQL_PASSWORD
ENV MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASSWORD
ENV MYSQL_PORT=$MYSQL_PORT

# Sao chép tập tin SQL tùy chỉnh vào thư mục khởi tạo của MySQL
# Các script trong thư mục này sẽ tự động được thực thi khi container khởi động
COPY ./init.sql /docker-entrypoint-initdb.d/

# Mở cổng 3306 (cổng mặc định của MySQL)
EXPOSE 3306
