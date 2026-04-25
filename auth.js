// ═══════════════════════════════════════════════════════════════════
// TANTECNO — Módulo compartido de autenticación con Supabase Auth
// ═══════════════════════════════════════════════════════════════════
// Uso en páginas internas:
//   <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
//   <script src="auth.js"></script>
//   <script>tantecnoAuth.requireLogin('panel.html')</script>
//
// Uso en login:
//   <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script>
//   <script src="auth.js"></script>
//   tantecnoAuth.signIn(email, password) → Promise<{ok, error}>
// ═══════════════════════════════════════════════════════════════════

(function(){
  const SUPABASE_URL='https://wqgatoyouzckgmsilagz.supabase.co'
  const SUPABASE_KEY='sb_publishable_2Ar5UzQLYoLzmPYq_Xd71A_kaIOzMDc'

  // El cliente Supabase tiene auto-refresh y persistencia en localStorage por default.
  if(typeof window.supabase==='undefined'||typeof window.supabase.createClient!=='function'){
    console.error('[tantecnoAuth] supabase-js no está cargado. Incluye <script src="https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2"></script> ANTES de auth.js')
    return
  }
  const sb=window.supabase.createClient(SUPABASE_URL,SUPABASE_KEY,{
    auth:{persistSession:true,autoRefreshToken:true,storageKey:'tantecno_sb_auth'}
  })

  // Exponemos el cliente para que páginas internas (catálogo, etc.) lo reutilicen
  // y compartan sesión sin crear múltiples instancias.
  window.tantecnoSb=sb

  // ──── CHEQUEO SÍNCRONO RÁPIDO ────
  // Lee el token directo del localStorage para responder en <1ms y evitar flash
  // de contenido protegido. NO valida que el token siga vigente — eso se hace después.
  function tieneTokenLocal(){
    try{
      const raw=localStorage.getItem('tantecno_sb_auth')
      if(!raw)return false
      const data=JSON.parse(raw)
      return !!(data&&data.access_token)
    }catch(e){return false}
  }

  // ──── PROTECCIÓN DE PÁGINAS INTERNAS ────
  // Llamar al INICIO del <head> de cada página protegida.
  // Si no hay token: redirige inmediato a login con ?redirect=...
  // Si hay token: deja cargar la página, y en background revalida la sesión.
  // Si la sesión asíncrona falla (token expirado, revocado): cierra sesión y redirige.
  function requireLogin(paginaActual){
    if(!tieneTokenLocal()){
      const params='?redirect='+encodeURIComponent(paginaActual||'panel.html')
      window.location.replace('login.html'+params)
      return
    }
    // Hay token local: validamos contra el servidor en background.
    sb.auth.getSession().then(function(res){
      const session=res&&res.data&&res.data.session
      if(!session){
        // Token inválido/expirado y no se pudo refrescar
        console.warn('[tantecnoAuth] sesión inválida, redirigiendo a login')
        signOut(paginaActual)
      }
    }).catch(function(err){
      console.warn('[tantecnoAuth] error validando sesión:',err)
      // No forzamos signOut aquí — puede ser un error de red transitorio.
      // El usuario sigue trabajando offline; al volver la red, se revalidará.
    })
  }

  // ──── LOGIN ────
  async function signIn(email,password){
    if(!email||!password){return {ok:false,error:'Ingresa email y contraseña.'}}
    try{
      const {data,error}=await sb.auth.signInWithPassword({email:email.trim(),password:password})
      if(error){
        // Mensajes claros según el tipo de error
        let msg='No fue posible iniciar sesión.'
        if(error.message){
          if(/invalid login/i.test(error.message))msg='Email o contraseña incorrectos.'
          else if(/email not confirmed/i.test(error.message))msg='Debes confirmar tu email antes de entrar.'
          else if(/network/i.test(error.message))msg='Error de conexión. Verifica tu internet.'
          else msg=error.message
        }
        return {ok:false,error:msg}
      }
      if(!data||!data.session)return {ok:false,error:'Sesión no creada. Intenta nuevamente.'}
      return {ok:true,user:data.user}
    }catch(e){
      console.error('[tantecnoAuth] excepción en signIn:',e)
      return {ok:false,error:'Error inesperado: '+(e.message||e)}
    }
  }

  // ──── LOGOUT ────
  async function signOut(redirectTo){
    try{await sb.auth.signOut()}catch(e){console.warn('[tantecnoAuth] error en signOut:',e)}
    // Por seguridad, también limpiamos manualmente el storage.
    try{localStorage.removeItem('tantecno_sb_auth')}catch(e){}
    // También removemos la clave vieja si quedó de versiones anteriores.
    try{localStorage.removeItem('tantecno_auth')}catch(e){}
    const params=redirectTo?'?redirect='+encodeURIComponent(redirectTo):''
    window.location.replace('login.html'+params)
  }

  // ──── HELPER: usuario actual ────
  async function getUser(){
    try{
      const {data}=await sb.auth.getUser()
      return data&&data.user||null
    }catch(e){return null}
  }

  // ──── EXPORT ────
  window.tantecnoAuth={
    requireLogin:requireLogin,
    signIn:signIn,
    signOut:signOut,
    getUser:getUser,
    sb:sb
  }
})();
