package com.example.demo.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS= Arrays.asList(
            new Student(101, "jasim"),
            new Student(102, "abdur rahman"),
            new Student(103, "abdulla")
            );

    @GetMapping("{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId){
        return STUDENTS.stream()
                .filter(item->studentId.equals(item.getStudentId()))
                .findFirst()
                .orElseThrow(()->new IllegalStateException("studentId "+studentId+" does not exist"));
    }
}
