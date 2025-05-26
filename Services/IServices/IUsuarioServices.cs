using Domain.DTO;
using Domain.Entities;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace WebApi29.Services.IServices
{
    public interface IUsuarioServices
    {
        //Read
        public Task<Response<List<Usuario>>> ObtenerUsuarios();
        //Read for Id
        public Task<Response<Usuario>> ById(int id);
        //Create
        public Task<Response<Usuario>> Crear(UsuarioRequest usuario);
        //Update
        public Task<Response<Usuario>> Actualizar(int id, UsuarioRequest request);
        //Delete
        public Task<Response<string>> Eliminar(int id);
    }
}