using Domain.DTO;
using Domain.Entities;
using Microsoft.EntityFrameworkCore;
using WebApi29.Context;
using WebApi29.Services.IServices;

namespace WebApi29.Services.Services
{
    public class UsuarioServices : IUsuarioServices
    {
        private readonly ApplicationDbContext _context;
        public UsuarioServices(ApplicationDbContext context)
        {
            _context = context;
        }

        //Lista de usuarios
        public async Task<Response<List<Usuario>>> ObtenerUsuarios()
        {
            try
            {

                List<Usuario> response = await _context.Usuarios.Include(x => x.Roles).ToListAsync();

                return new Response<List<Usuario>>(response, "Lista de usuarios");

            }
            catch (Exception ex)
            {

                throw new Exception("Ocurrio un error " + ex.Message);
            }
        }

        //Buscar usuario por id
        public async Task<Response<Usuario>> ById(int id)
        {
            try
            {
                Usuario usuario = await _context.Usuarios.Include(u => u.Roles).FirstOrDefaultAsync(x => x.PkUsuario == id);
                return new Response<Usuario>(usuario);
            }
            catch (Exception ex)
            {
                throw new Exception("Ocurrio un error" + ex.Message);
            }
        }

        //Crear usuario
        public async Task<Response<Usuario>> Crear(UsuarioRequest usuario)
        {
            try
            {
                Usuario usuario1 = new Usuario()
                {
                    Nombre = usuario.Nombre,
                    UserName = usuario.UserName,
                    Password = usuario.Password,
                    FkRol = usuario.FkRol
                };

                _context.Usuarios.Add(usuario1);
                await _context.SaveChangesAsync();

                return new Response<Usuario>(usuario1);
            }
            catch (Exception ex)
            {
                throw new Exception("Ocurrio un error " + ex.Message);
            }
        }

        //Actualizar datos
        public async Task<Response<Usuario>> Actualizar(int id, UsuarioRequest request)
        {
            try
            {
                var usuario = await _context.Usuarios.FirstOrDefaultAsync(x => x.PkUsuario == id);

                if (usuario == null)
                    return new Response<Usuario>("Usuario no encontrado");

                usuario.Nombre = request.Nombre;
                usuario.UserName = request.UserName;
                usuario.Password = request.Password;
                usuario.FkRol = request.FkRol;

                _context.Usuarios.Update(usuario);
                await _context.SaveChangesAsync();

                return new Response<Usuario>(usuario, "Usuario actualizado correctamente");
            }
            catch (Exception ex)
            {
                throw new Exception("Ocurrió un error " + ex.Message);
            }
        }


        //Borrar datos
        public async Task<Response<string>> Eliminar(int id)
        {
            try
            {
                var usuario = await _context.Usuarios.FirstOrDefaultAsync(x => x.PkUsuario == id);

                if (usuario == null)
                    return new Response<string>("Usuario no encontrado");

                _context.Usuarios.Remove(usuario);
                await _context.SaveChangesAsync();

                return new Response<string>("Usuario eliminado correctamente");
            }
            catch (Exception ex)
            {
                throw new Exception("Ocurrió un error " + ex.Message);
            }
        }


    }
}