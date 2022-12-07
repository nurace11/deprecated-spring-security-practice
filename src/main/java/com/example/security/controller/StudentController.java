package com.example.security.controller;

import com.example.security.entity.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1L, "Rex"),
            new Student(2L, "T-Rex"),
            new Student(3L, "FinalStudent")
    );

    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable("studentId") Long studentId){
        System.out.println("getStudent ");
        return STUDENTS.stream()
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student " + studentId + " does not exists "));
    }
}
