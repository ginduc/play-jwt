package dynobjx.playjwt

import scala.concurrent.Future
import play.api.mvc._
import play.api.mvc.Results._
import play.api.Play
import play.api.Play.current
import play.api.libs.json.JsValue
import play.api.http.HeaderNames._

/**
 * Play Framework 2.3.x wrappers for JSON Web Token-based authentication
 *
 * http://openid.net/specs/draft-jones-json-web-token-07.html#ExampleJWT
 *
 * Created by ginduc on 2/12/15.
 */

class JWTSignedRequest[A](val jwt: String,
  request: Request[A]) extends WrappedRequest[A](request) {
  def userInfo = JWTSession.decode(jwt).getSubject
}

object Signed extends ActionBuilder[JWTSignedRequest] {
  private val realm = Play.application.configuration.getString("playjwt.realm").getOrElse("Protected Realm")

  def invokeBlock[A](req: Request[A], block: (JWTSignedRequest[A]) => Future[Result]) = {
    req.headers.get(AUTHORIZATION) map { token =>
      if (JWTSession.verify(token)) {
        block(new JWTSignedRequest(token, req))
      } else {
        Future.successful(Forbidden)
      }
    } getOrElse {
      Future.successful(Unauthorized.withHeaders(WWW_AUTHENTICATE -> """Basic realm="%s"""".format(realm)))
    }
  }
}

trait PlayJWTImplicits {
  implicit class JWTSignedResult(result: Result) {
    def withSignedJWT(user: JsValue)(implicit request: RequestHeader): Result = {
      result.withHeaders(AUTHORIZATION -> (JWTSession.tokenPrefix + JWTSession.sign(user)))
    }
  }
}
