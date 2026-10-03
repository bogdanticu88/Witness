# Deliberately vulnerable test application for Witness. Never deploy.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/ ./src/
RUN dotnet publish src/Acme.Orders.Web/Acme.Orders.Web.csproj -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app ./
COPY documents/ ./documents/
ENV ASPNETCORE_URLS=http://+:8080 \
    Database__Path=/tmp/acme-orders.db
EXPOSE 8080
ENTRYPOINT ["dotnet", "Acme.Orders.Web.dll"]
