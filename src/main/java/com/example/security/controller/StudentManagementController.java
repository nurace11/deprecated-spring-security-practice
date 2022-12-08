package com.example.security.controller;

import com.example.security.entity.Student;
import com.example.security.security.ApplicationUserRole;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {
    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1L, "Rex"),
            new Student(2L, "T-Rex"),
            new Student(3L, "FinalStudent")
    );

    private final String adminRole = ApplicationUserRole.ADMIN.name();

    @GetMapping
    // hasRole() hasAnyRole() hasAuthority() hasAnyAuthority()
    // @PreAuthorize annotation will work if there is @EnableGlobalMethodSecurity(prePostEnabled = true) annotation in the SecurityConfig class
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_MODERATOR')")
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void deleteStudent(@PathVariable("studentId") Long studentId) {
        System.out.println(studentId);
    }

    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void updateStudent(@PathVariable Long studentId,
                              @RequestBody Student student){
        System.out.println(String.format("%d %s", studentId, student));
    }
}
