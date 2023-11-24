import io.github.kamilszewc.totp.Totp
import spock.lang.Specification

class TotpTest extends Specification {

    def "Check code for predefined time and secret"() {
        when:
        def code = Totp.getCode("SDFWEFWEFWE33DFSG2",1671980236)
        then:
        code == "783109"
    }

    def "Check code validity for predefined time"() {
        when:
        def interval = Totp.getCodeRemainingValidityTime(0, 30, 1671980236)
        then:
        interval == 14
    }
}
