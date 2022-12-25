import io.github.kamilszewc.Totp
import spock.lang.Specification

class TotpTest extends Specification {

    def "Check code for predefined time and secret"() {
        when:
        def code = Totp.getCode("SDFWEFWEFWE33DFSG2",1671980236)
        then:
        code == "783109"
    }
}
