using Domain.DTO;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using WebApi29.Context;
using WebApi29.Services.IServices;

namespace WebApi29.Services.Services
{
    public class RolServices : IRolServices
    {
        private readonly ApplicationDbContext _context;

        public RolServices(ApplicationDbContext context)
        {
            _context = context;
        }

        //Lista de roles
        public async Task<Response<List<Rol>>> GetAllRoles()
        {
            try
            {
                var roles = await _context.Roles.ToListAsync();

                return new Response<List<Rol>>(roles, "Lista de roles");
            }
            catch (Exception ex)
            {

                throw new Exception("Ocurrio un error " + ex.Message);
            }
        }

        //Buscar roles por id del rol
        public async Task<Response<Rol>> RolesById(int id)
        {
            try
            {
                var rol = await _context.Roles.FindAsync(id);

                if (rol == null)
                {
                    return new Response<Rol>(rol, "Rol no encontrado");
                }

                return new Response<Rol>(rol, "Rol encontrado");
            }
            catch (Exception ex)
            {

                throw new Exception("Ocurrio un error " + ex.Message);
            }
        }

        //Crear rol
        public async Task<Response<Rol>> Crear(RolRequest request)
        {
            try
            {
                var rol = new Rol()
                {
                    Nombre = request.Nombre,
                };

                _context.Roles.Add(rol);
                await _context.SaveChangesAsync();

                return new Response<Rol>(rol, "Rol creado");
            }
            catch (Exception ex)
            {

                throw new Exception("Ocurrio un error " + ex.Message);
            }
        }

        //Actualizar rol
        public async Task<Response<string>> Actualizar(int id, RolRequest request)
        {
            var rol = await _context.Roles.FindAsync(id);

            if (rol == null)
            {
                return new Response<string>("Rol no encontrado");
            }

            rol.Nombre = request.Nombre;
            await _context.SaveChangesAsync();

            return new Response<string>("Rol actualizado exitosamente");
        }

        //Borrar rol
        public async Task<Response<string>> Eliminar(int id)
        {
            var rol = await _context.Roles.FindAsync(id);
            if (rol == null)
            {
                return new Response<string>("Rol no encontrado");
            }

            _context.Roles.Remove(rol);
            await _context.SaveChangesAsync();

            return new Response<string>("Rol eliminado");
        }

    }
}