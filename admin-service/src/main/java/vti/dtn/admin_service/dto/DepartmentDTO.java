package vti.dtn.admin_service.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@Builder
public class DepartmentDTO {
    private String name;

    private String type;

    @JsonFormat(pattern = "yyyy-MM-dd")
    private Date createdDate;
}
