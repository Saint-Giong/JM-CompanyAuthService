package rmit.saintgiong.authapi.internal.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CompanyRegistrationRequestDto {

    @NotBlank(message = "Company name is required")
    private String companyName;

    @NotBlank(message = "Email is required")
    @Email(message = "Email must meet standard formatting: contains exactly one '@' symbol, at least one '.' after the '@', total length less than 255 characters, and no spaces or prohibited characters")
    @Size(max = 255, message = "Email total length must be less than 255 characters")
    @Pattern(
        regexp = "^[^@]*@[^@]*\\.[^@]*$",
        message = "Email must contain exactly one '@' symbol and at least one '.' after the '@'"
    )
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(
        regexp = "^(?=.*[0-9])(?=.*[!@#$%^&*])(?=.*[A-Z]).+$",
        message = "Password must contain at least 1 number, 1 special character, and 1 uppercase letter"
    )
    private String password;

    @NotBlank(message = "Country is required")
    private String country;

    @Pattern(
            regexp = "^\\+\\d{1,3}\\d{1,12}$",
            message = "Phone number must start with '+' followed by 1-3 digit country code and 1-12 digits"
    )
    private String phoneNumber;

    private String city;

    private String address;
}
