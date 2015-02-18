package dynobjx.playjwt;

import play.*;
import play.mvc.*;
import play.libs.*;
import play.libs.F.*;

/**
 * Java implementation of the JWT-Signed Simple Action using Play JWT
 *
 * Created by ginduc on 2/18/15.
 */
public class JWTSignedAction extends play.mvc.Action.Simple {
    private static final String AUTHORIZATION = "Authorization";
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";
    private static final String APP_REALM = Play.application().configuration().getString("playjwt.realm");
    private static final String AUTH_HEADER_PREFIX = "Bearer ";
    private String realm;

    public JWTSignedAction() {
        super();

        if (APP_REALM != null) {
            realm = String.format("Basic realm=\"%s\"", APP_REALM);
        } else {
            realm = "Basic realm=\"Protected Realm\"";
        }
    }

    public F.Promise<Result> call(Http.Context ctx) throws Throwable {
        try {
            final String authHeader = ctx.request().getHeader(AUTHORIZATION);

            if (authHeader != null && authHeader.startsWith(AUTH_HEADER_PREFIX)) {
                final String token = authHeader.substring(AUTH_HEADER_PREFIX.length());
                if (JWTSession.verify(token)) {
                    return delegate.call(ctx);
                }
            }
        } catch (Exception e) {
            Logger.error("Error during session authentication: " + e);
        }

        ctx.response().setHeader(WWW_AUTHENTICATE, realm);
        return Promise.pure((Result) forbidden());
    }
}
