#See https://aka.ms/containerfastmode to understand how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src/Poort8.Ishare.Common
COPY ["Poort8.Ishare.Common.csproj", "."]
RUN dotnet restore
COPY ["Poort8.Ishare.Core/Poort8.Ishare.Core.csproj", "Poort8.Ishare.Core/"]
RUN dotnet restore "./Poort8.Ishare.Core/Poort8.Ishare.Core.csproj"
COPY . .
WORKDIR "/src/Poort8.Ishare.Common"
RUN dotnet build "Poort8.Ishare.Common.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Poort8.Ishare.Common.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Poort8.Ishare.Common.dll"]