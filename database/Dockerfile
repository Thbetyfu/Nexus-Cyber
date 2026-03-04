FROM mysql:8.0
ENV MYSQL_ROOT_PASSWORD=nexus_root_2024
ENV MYSQL_DATABASE=ktp_database
ENV MYSQL_USER=ktp_user
ENV MYSQL_PASSWORD=ktp_password_123
COPY init_db.sql /docker-entrypoint-initdb.d/
EXPOSE 3306
