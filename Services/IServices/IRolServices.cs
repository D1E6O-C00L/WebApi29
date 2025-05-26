using Domain.DTO;
using Domain.Entities;

namespace WebApi29.Services.IServices
{
    public interface IRolServices
    {
        //Lista de roles
        public Task<Response<List<Rol>>> GetAllRoles();

        //Buscar rol por id del rol
        public Task<Response<Rol>> RolesById(int id);

        //Crear rol
        public Task<Response<Rol>> Crear(RolRequest request);

        //Actualizar el rol
        public Task<Response<string>> Actualizar(int id, RolRequest request);

        //Eliminar el rol
        public Task<Response<string>> Eliminar(int id);

    }
}